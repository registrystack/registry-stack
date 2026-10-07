use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::Algorithm;
use registry_casework_core::{check_routing_policy, CaseworkProject, ConfigLoadError};
use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    is_sha256_label, sha256_uri, ConfigBlockError, PackageConfig, PackageDigestMismatch,
    PackageError, PackageErrorKind, PackageLimits, RemovedKey, RuntimeConfigLoader,
    RuntimeEnvelope, SecretResolver, VerifiedPackage, REMOVED_OIDC_JWKS_URI,
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
use serde::Deserialize;
use thiserror::Error;

/// The command that builds a Casework package, named in every package refusal.
pub const PACKAGE_COMMAND: &str = "caseworkctl package";
/// The manifest earlier Casework packages carried. A package root holding it
/// is refused, naming the command that writes the current package.
pub const RETIRED_PACKAGE_MANIFEST_FILE: &str = "casework.package.json";
pub const RUNTIME_CONFIG_API_VERSION: &str = "registry.registrystack.org/casework-runtime/v1alpha1";
pub const RUNTIME_CONFIG_KIND: &str = "CaseworkRuntimeConfig";
pub const POLICY_FILE: &str = "casework.yaml";

/// The envelope every Casework runtime configuration carries.
pub const CASEWORK_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_CONFIG_API_VERSION,
    kind: RUNTIME_CONFIG_KIND,
};

/// Keys an earlier Casework runtime configuration accepted, each refused with
/// the key that replaced it.
pub const CASEWORK_REMOVED_KEYS: &[RemovedKey] = &[
    REMOVED_OIDC_JWKS_URI,
    RemovedKey {
        path: "authentication.oidc.principalClaim",
        replacement: "declare accessProfiles[].principalClaim in casework.yaml",
    },
    RemovedKey {
        path: "package.expectedPolicyDigest",
        replacement: "package.expectedDigest, the digest `caseworkctl package` reports",
    },
];
/// The RFC 9068 access-token media type this runtime verifies. The pair of
/// spellings it admits is derived from this one value, never authored, so no
/// deployment can widen it to an ordinary JWT.
const CASEWORK_ACCESS_TOKEN_TYPE: &str = "at+jwt";
const MAXIMUM_PACKAGE_FILE_BYTES: usize = 1024 * 1024;
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
/// `casework.yaml` and every source description the project names.
pub fn package_inputs(project: &CaseworkProject) -> Result<BTreeSet<String>, RuntimeConfigError> {
    let mut inputs = BTreeSet::from([POLICY_FILE.to_owned()]);
    for source in &project.sources {
        if normalized_relative_path(&source.description).is_none()
            || !inputs.insert(source.description.clone())
        {
            return Err(RuntimeConfigError::SourceDescription);
        }
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
    verify_casework_contents(project, &verified)?;
    Ok(verified)
}

fn verify_casework_envelope(
    package: &RuntimePackageConfig,
) -> Result<VerifiedPackage, RuntimeConfigError> {
    if std::fs::symlink_metadata(package.root.join(RETIRED_PACKAGE_MANIFEST_FILE)).is_ok() {
        return Err(RuntimeConfigError::RetiredPackageManifest);
    }
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
    verified: &VerifiedPackage,
) -> Result<(), RuntimeConfigError> {
    let expected = package_inputs(project)?;
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
    source_descriptions: BTreeMap<String, Vec<u8>>,
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
    pub fn source_description(&self, path: &str) -> Option<&[u8]> {
        self.source_descriptions.get(path).map(Vec::as_slice)
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

/// Validate one imported BReg description through the adapter's owning strict
/// decoder without resolving runtime bindings or secrets. Returns each request
/// entity's routing metadata, keyed by entity. A refusal distinguishes a
/// policy that names a field the description does not publish from a
/// description that does not meet the adapter contract.
pub fn validate_breg_source_description(
    source: &registry_casework_core::SourcePolicy,
    bytes: &[u8],
) -> Result<
    BTreeMap<String, registry_casework_core::RoutingSourceMetadata>,
    registry_casework_breg::DescriptionRefusal,
> {
    registry_casework_breg::check_description_input(source, bytes)
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
    #[serde(default)]
    pub sources: BTreeMap<String, registry_casework_breg::BregBinding>,
    #[serde(default)]
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
    pub url: String,
    /// Shorthand for `auth` with no header: the secret is presented as
    /// `Authorization: Bearer`. Exactly one of this and `auth` is configured.
    #[serde(default)]
    pub bearer_token_ref: Option<String>,
    #[serde(default)]
    pub auth: Option<ReviewCompletionAuthConfig>,
    #[serde(default = "default_review_completion_timeout_ms")]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS,
            max = MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS
        ))
    )]
    pub timeout_milliseconds: u64,
    #[serde(default = "default_review_completion_attempts")]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MINIMUM_REVIEW_COMPLETION_ATTEMPTS,
            max = MAXIMUM_REVIEW_COMPLETION_ATTEMPTS
        ))
    )]
    pub maximum_attempts: u32,
    #[serde(default = "default_review_completion_retry_seconds")]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MINIMUM_REVIEW_COMPLETION_RETRY_SECONDS,
            max = MAXIMUM_REVIEW_COMPLETION_RETRY_SECONDS
        ))
    )]
    pub retry_seconds: u64,
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
    pub issuer: String,
    pub exchange_audience: String,
    pub signing_key_ref: String,
    /// Service client IDs mapped to their one protected resource audience.
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
    #[serde(default)]
    pub expected_digest: Option<String>,
    /// The package digest of a package the operator has accepted will strand
    /// in-flight work pinned under an earlier package. Startup and `doctor`
    /// refuse such a package unless this names its exact digest, so an
    /// acknowledgement never carries over to a later package.
    #[serde(default)]
    pub acknowledge_stranded_work: Option<String>,
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
    #[serde(flatten)]
    pub provider: OidcIssuerConfig,
    /// The clients admitted and the assertion authorities each may exchange
    /// a subject token from, keyed by client identifier. An empty
    /// `assertionIssuers` map applies no rule; see
    /// [`registry_platform_oidc::TokenVerifierConfig::assertion_issuers`].
    #[serde(flatten)]
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

impl RuntimeConfig {
    /// Load and validate the operator document, reading the authored project
    /// and its package beside it.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    /// The shared runtime configuration loader under Casework's envelope and
    /// removed keys.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(CASEWORK_RUNTIME_ENVELOPE).removed_keys(CASEWORK_REMOVED_KEYS)
    }

    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.package.root.join(POLICY_FILE)
    }

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if self.api_version != RUNTIME_CONFIG_API_VERSION {
            return Err(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != RUNTIME_CONFIG_KIND {
            return Err(RuntimeConfigError::InvalidKind);
        }
        let Some(identity) = &self.identity else {
            return Err(RuntimeConfigError::MissingIdentity);
        };
        if !valid_database_id(&identity.database_id) {
            return Err(RuntimeConfigError::InvalidDatabaseId);
        }
        self.package.shared().check()?;
        self.secret_providers.check()?;
        self.audit.destination()?;
        self.validate_secret_references()?;
        if self
            .package
            .acknowledge_stranded_work
            .as_deref()
            .is_some_and(|acknowledged| !is_sha256_label(acknowledged))
        {
            return Err(RuntimeConfigError::InvalidStrandedWorkAcknowledgement);
        }
        let package = self.capture_package_after_verification(|| {})?;
        let project = package.project();
        if !self.listener.is_valid() {
            return Err(RuntimeConfigError::InvalidListener);
        }
        if let Some(metrics_listener) = &self.metrics_listener {
            metrics_listener.validate(&self.listener)?;
        }
        self.authentication.oidc.provider.check(
            "authentication.oidc",
            self.listener.tls_termination == TlsTermination::DevelopmentLoopback,
        )?;
        self.authentication
            .oidc
            .clients
            .check("authentication.oidc")?;
        // An empty client list admits every client the issuer verifies, so a
        // deployment that simply forgot the field would accept a token minted
        // for an unrelated application in the same realm. Development loopback
        // keeps that convenience; a deployment behind an operator-controlled
        // terminator must name the clients it admits.
        if self.listener.tls_termination == TlsTermination::OperatorControlledUpstream
            && self.authentication.oidc.clients.allowed_clients.is_empty()
        {
            return Err(RuntimeConfigError::AllowedClientsRequired);
        }
        if self.authentication.oidc.scope_claim.is_empty()
            || self.authentication.oidc.human_identity.claim.is_empty()
            || self.authentication.oidc.human_identity.value.is_empty()
            || self.authentication.oidc.human_identity.claim == self.authentication.oidc.scope_claim
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        self.validate_project_bindings(project)?;
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidDatabaseReference);
        }
        if self
            .review_completion_destinations
            .iter()
            .any(|(id, destination)| {
                id.is_empty()
                    || !valid_review_completion_url(&destination.url)
                    || !(MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS
                        ..=MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS)
                        .contains(&destination.timeout_milliseconds)
                    || !(MINIMUM_REVIEW_COMPLETION_ATTEMPTS..=MAXIMUM_REVIEW_COMPLETION_ATTEMPTS)
                        .contains(&destination.maximum_attempts)
                    || !(MINIMUM_REVIEW_COMPLETION_RETRY_SECONDS
                        ..=MAXIMUM_REVIEW_COMPLETION_RETRY_SECONDS)
                        .contains(&destination.retry_seconds)
            })
        {
            return Err(RuntimeConfigError::InvalidSourceBindings);
        }
        self.validate_source_bindings()?;
        #[cfg(not(feature = "postgres-test"))]
        if self.database.test_only_plaintext {
            return Err(RuntimeConfigError::PlaintextDatabase);
        }
        Ok(())
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
        self.validate_project_bindings(package.project())?;
        Ok(package)
    }

    fn capture_package_after_verification(
        &self,
        after_verification: impl FnOnce(),
    ) -> Result<LoadedCaseworkPackage, RuntimeConfigError> {
        let verified = verify_casework_envelope(&self.package)?;
        after_verification();

        let policy_bytes = capture_verified_file(&self.package.root, &verified, POLICY_FILE)?;
        let project = CaseworkProject::read(
            &self.package.root.join(POLICY_FILE).display().to_string(),
            &policy_bytes,
        )
        .map(|decoded| decoded.value)
        .map_err(|report| RuntimeConfigError::Project(ConfigLoadError::Refused(report)))?;
        verify_casework_contents(&project, &verified)?;

        let mut source_descriptions = BTreeMap::new();
        for source in &project.sources {
            let bytes =
                capture_verified_file(&self.package.root, &verified, source.description.as_str())?;
            source_descriptions.insert(source.description.clone(), bytes);
        }
        validate_project_source_description_bytes(&project, &source_descriptions)?;

        Ok(LoadedCaseworkPackage {
            digest: verified.digest().to_owned(),
            project,
            source_descriptions,
        })
    }

    fn validate_project_bindings(
        &self,
        project: &CaseworkProject,
    ) -> Result<(), RuntimeConfigError> {
        if project
            .access_profiles
            .iter()
            .any(|profile| profile.principal_claim == self.authentication.oidc.human_identity.claim)
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        if let Some(authority) = &self.task_authority {
            if !registry_platform_httputil::valid_resource_uri(&authority.issuer)
                || !registry_platform_httputil::valid_resource_uri(&authority.exchange_audience)
                || self.authentication.oidc.clients.allowed_clients.is_empty()
                || authority.status_clients.len() > 64
                || authority.status_clients.iter().any(|(client, resource)| {
                    !self
                        .authentication
                        .oidc
                        .clients
                        .allowed_clients
                        .contains(client)
                        || !registry_platform_httputil::valid_resource_uri(resource)
                })
                || project.task_templates.iter().any(|template| {
                    template.agent.issuer != self.authentication.oidc.provider.issuer
                        || !self
                            .authentication
                            .oidc
                            .clients
                            .allowed_clients
                            .contains(&template.client)
                        || !registry_platform_httputil::valid_resource_uri(&template.resource)
                })
            {
                return Err(RuntimeConfigError::InvalidOidc);
            }
        } else if !project.task_templates.is_empty() {
            return Err(RuntimeConfigError::InvalidOidc);
        }

        let declared_sources = project
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<BTreeSet<_>>();
        let configured_sources = self
            .sources
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if self.sources.keys().any(String::is_empty) || configured_sources != declared_sources {
            return Err(RuntimeConfigError::InvalidSourceBindings);
        }
        let source_context_kinds = project
            .review_kinds
            .iter()
            .filter(|kind| {
                kind.context_strategy == registry_casework_core::ReviewContextStrategy::Source
            })
            .map(|kind| kind.id.as_str())
            .collect::<BTreeSet<_>>();
        if project.review_producers.iter().any(|producer| {
            producer
                .kinds
                .iter()
                .any(|kind| source_context_kinds.contains(kind.as_str()))
                && producer
                    .source_namespaces
                    .iter()
                    .any(|namespace| !configured_sources.contains(namespace.as_str()))
        }) {
            return Err(RuntimeConfigError::InactiveReviewSourceNamespace);
        }

        let declared_destinations = project
            .review_producers
            .iter()
            .filter_map(|producer| producer.completion.as_ref())
            .map(|completion| completion.destination_id.as_str())
            .collect::<BTreeSet<_>>();
        let configured_destinations = self
            .review_completion_destinations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if !declared_destinations.is_subset(&configured_destinations) {
            return Err(RuntimeConfigError::InvalidSourceBindings);
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
        for (source_id, binding) in &self.sources {
            for (member, reference) in [
                ("clientIdRef", &binding.client_id_ref),
                ("clientAssertionKeyRef", &binding.client_assertion_key_ref),
                ("webhookSecretRef", &binding.webhook_secret_ref),
            ] {
                references.push((format!("sources.{source_id}.{member}"), reference));
            }
            if let Some(reference) = &binding.trusted_root_certificates_ref {
                references.push((
                    format!("sources.{source_id}.trustedRootCertificatesRef"),
                    reference,
                ));
            }
        }
        for (destination_id, destination) in &self.review_completion_destinations {
            let path = format!("reviewCompletionDestinations.{destination_id}");
            match (&destination.bearer_token_ref, &destination.auth) {
                (Some(reference), None) => {
                    references.push((format!("{path}.bearerTokenRef"), reference));
                }
                (None, Some(auth)) => {
                    if auth
                        .header
                        .as_deref()
                        .is_some_and(|header| !valid_review_completion_header_name(header))
                    {
                        return Err(RuntimeConfigError::InvalidReviewCompletionAuth {
                            path: format!("{path}.auth.header"),
                        });
                    }
                    references.push((format!("{path}.auth.secretRef"), &auth.secret_ref));
                }
                _ => {
                    return Err(RuntimeConfigError::InvalidReviewCompletionAuth {
                        path: format!("{path}.auth"),
                    });
                }
            }
        }
        for (field, raw) in references {
            self.secret_providers.check_reference(&field, raw)?;
        }
        Ok(())
    }

    /// Refuse a bound source that breaks one of the adapter's binding rules.
    /// This runs at configuration load, before secrets are resolved or any
    /// adapter is built, so an operator sees the refusal without the runtime
    /// ever starting. The refusal names the member that broke the rule and
    /// the rule itself, never the configured value.
    fn validate_source_bindings(&self) -> Result<(), RuntimeConfigError> {
        for (source_id, binding) in &self.sources {
            registry_casework_breg::validate_binding_input(binding).map_err(|rule| {
                RuntimeConfigError::InvalidSourceBinding {
                    path: format!("sources.{source_id}.{}", rule.field()),
                    reason: rule.reason(),
                }
            })?;
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
    /// UserInfo JWT, or any other JWT minted for this audience is not an
    /// access token, and admitting one would let a credential issued for
    /// another purpose claim, draft, and act on casework.
    pub(crate) fn verifier_profile(&self) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            self.authentication.oidc.provider.issuer.clone(),
            vec![self.authentication.oidc.provider.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set(CASEWORK_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(self.authentication.oidc.clients.allowed_clients.clone())
        .with_assertion_issuers(self.authentication.oidc.clients.assertion_issuers.clone())
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

fn validate_project_source_description_bytes(
    project: &CaseworkProject,
    descriptions: &BTreeMap<String, Vec<u8>>,
) -> Result<(), RuntimeConfigError> {
    let queues = project
        .queues
        .iter()
        .map(|queue| queue.id.clone())
        .collect::<BTreeSet<_>>();
    for source in &project.sources {
        if source.adapter != "breg"
            || source.requests.is_empty()
            || source.requests.len() > registry_casework_breg::MAXIMUM_REQUEST_ENTITIES
        {
            return Err(RuntimeConfigError::SourceDescription);
        }
        let bytes = descriptions
            .get(&source.description)
            .ok_or(RuntimeConfigError::SourceDescription)?;
        let metadata = validate_breg_source_description(source, bytes)
            .map_err(|_| RuntimeConfigError::SourceDescription)?;
        for request in &source.requests {
            check_routing_policy(
                &request.queue,
                &request.projection,
                &request.routing,
                &queues,
                Some(
                    metadata
                        .get(&request.entity)
                        .ok_or(RuntimeConfigError::SourceDescription)?,
                ),
            )
            .map_err(|_| RuntimeConfigError::SourceDescription)?;
        }
    }
    Ok(())
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::RuntimeConfigErrorKind;
    use registry_platform_config::{
        MAX_ASSERTION_ISSUERS_PER_CLIENT, MAX_ASSERTION_ISSUER_BYTES, MAX_ASSERTION_ISSUER_CLIENTS,
        MAX_ASSERTION_ISSUER_CLIENT_BYTES, SUM_FILE,
    };
    use registry_platform_oidc::is_access_token_typ_pair;

    #[test]
    fn completion_destination_requires_a_complete_credential_free_url() {
        for valid in [
            "https://casework.example.test/v1/completions",
            "http://127.0.0.1:8080/completions",
            "http://[::1]:8080/completions",
        ] {
            assert!(valid_review_completion_url(valid), "{valid}");
        }
        for invalid in [
            "https://",
            "https://user@casework.example.test/completions",
            "https://casework.example.test/completions?token=secret",
            "https://casework.example.test/completions#fragment",
            "http://casework.example.test/completions",
        ] {
            assert!(!valid_review_completion_url(invalid), "{invalid}");
        }
    }

    const SOURCE_PROJECT: &str = r#"apiVersion: registry.registrystack.org/casework/v1alpha1
kind: CaseworkProject
casework: {id: packaged-review, version: "1"}
accessProfiles:
  - {id: staff, principalClaim: sub, requiredScopes: [staff], role: staff}
  - {id: supervisor, principalClaim: sub, requiredScopes: [supervisor], role: supervisor}
  - {id: administrator, principalClaim: sub, requiredScopes: [admin], role: administrator}
queues: [{id: review, label: Review}]
sources:
  - id: professional
    adapter: breg
    description: sources/professional.json
    requests: [{entity: correction, queue: review}]
"#;

    const SOURCE_CONTEXT_REVIEW_PROJECT: &str = r#"apiVersion: registry.registrystack.org/casework/v1alpha1
kind: CaseworkProject
casework: {id: packaged-review, version: "1"}
accessProfiles:
  - {id: staff, principalClaim: sub, requiredScopes: [staff], role: staff}
  - {id: supervisor, principalClaim: sub, requiredScopes: [supervisor], role: supervisor}
  - {id: administrator, principalClaim: sub, requiredScopes: [admin], role: administrator}
  - {id: requester, principalClaim: sub, requiredScopes: [requester], role: requester}
queues: [{id: review, label: Review}]
sources:
  - id: professional
    adapter: breg
    description: sources/professional.json
    requests: [{entity: correction, queue: review}]
reviewKinds:
  - id: correction
    version: "1"
    purpose: approval
    contextStrategy: source
    stages:
      - {id: review, queue: review, decidingProfiles: [staff], requiredApprovals: 1}
    retention: {terminalDays: 30, accountabilityDays: 90}
    displaySchema:
      type: object
      additionalProperties: false
      required: [summary]
      properties: {summary: {type: string, maxLength: 160}}
reviewProducers:
  - id: registry
    profile: requester
    issuer: https://registry.example.test
    subject: registry-service
    sourceNamespaces: [professional]
    kinds: [correction]
    recoveryDays: 7
"#;

    const SOURCE_DESCRIPTION: &str = r#"{
  "apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1",
  "kind":"BRegCaseworkSourceDescription",
  "origin":"bregctl explain change-requests",
  "authority":"none",
  "sourceId":"professional",
  "sourceRevision":"sha256:source-revision",
  "request":{
    "requestEntity":"correction",
    "requestRoute":"corrections",
    "review":{"authority":"casework-main","policyId":"registry-correction"},
    "onApproved":{"mode":"manual"},
    "fields":[],
    "contractFingerprint":"sha256:contract",
    "application":{}
  }
}
"#;

    fn write_package_with_project(root: &Path, project: &str) -> VerifiedPackage {
        std::fs::create_dir_all(root.join("sources")).unwrap();
        std::fs::write(root.join("casework.yaml"), project).unwrap();
        std::fs::write(root.join("sources/professional.json"), SOURCE_DESCRIPTION).unwrap();
        registry_platform_config::write_sum_file(root, None, &package_limits(), PACKAGE_COMMAND)
            .unwrap()
    }

    fn canonical_tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
    }

    fn write_operator(root: &Path, document: &serde_json::Value) -> PathBuf {
        let operator = root.join("operator.yaml");
        std::fs::write(&operator, serde_norway::to_string(document).unwrap()).unwrap();
        operator
    }

    fn write_package(root: &Path) -> VerifiedPackage {
        write_package_with_project(root, SOURCE_PROJECT)
    }

    fn operator_document(package: &Path, tls: &str) -> String {
        serde_norway::to_string(&operator_value(package, tls)).unwrap()
    }

    /// A production fixture names the one client it admits, as a production
    /// deployment must; a loopback fixture leaves the list empty.
    fn operator_value(package: &Path, tls: &str) -> serde_json::Value {
        let root = package.parent().expect("package parent");
        let mut document = serde_json::json!({
            "apiVersion": RUNTIME_CONFIG_API_VERSION,
            "kind": RUNTIME_CONFIG_KIND,
            "identity": {"databaseId": "casework-test"},
            "package": {"root": package},
            "listener": {"bind": "127.0.0.1:8100", "tlsTermination": tls},
            "secretProviders": {"file": {"root": root.join("secrets")}, "environment": {}},
            "database": {
                "runtimeUrlRef": "secret:env/RUNTIME",
                "migrationUrlRef": "secret:env/MIGRATION"
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:casework"
            }},
            "audit": {"path": root.join("audit.ndjson"), "hashKeyRef": "secret:file/audit"},
            "sources": {"professional": {
                "baseUrl": "https://registry.example.test",
                "readerProfile": "casework-reader",
                "tokenEndpoint": "https://identity.example.test/token",
                "clientIdRef": "secret:file/client-id",
                "clientAssertionKeyRef": "secret:file/client-key",
                "webhookSecretRef": "secret:file/webhook",
                "eventSource": "urn:registrystack:registry:professional:instance:pilot"
            }}
        });
        if tls == "operator-controlled-upstream" {
            document["authentication"]["oidc"]["allowedClients"] =
                serde_json::json!(["casework-console"]);
        }
        document
    }

    /// The commented alternative in the operator example must be loadable
    /// exactly as written, and its refusal must name the reference an operator
    /// has to go and fix.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_static_jwks_source_loads_and_names_its_reference_when_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let secrets_root = root.path().join("secrets");
        std::fs::create_dir(&secrets_root).unwrap();
        std::fs::write(
            secrets_root.join("jwks.json"),
            br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(
            secrets_root.join("jwks.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"kind": "static", "documentRef": "secret:file/jwks.json"});
        let operator = root.path().join("operator.yaml");
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();

        let mut config = RuntimeConfig::load(&operator).expect("static JWKS source is accepted");
        assert!(matches!(
            &config.authentication.oidc.provider.jwks_source,
            JwksSource::Static { document_ref } if document_ref == "secret:file/jwks.json"
        ));

        let secrets = SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            &secrets_root,
        )
        .unwrap();
        let message = config
            .oidc_verifier(&secrets)
            .await
            .map(|_| ())
            .expect_err("a group-readable JWKS document is refused")
            .to_string();
        assert!(
            message.contains("secret:file/jwks.json") && message.contains("0400 or 0600"),
            "the failure does not name the reference and the mode rule: {message}"
        );

        let literal_secret = "literal-jwks-credential-canary";
        let JwksSource::Static { document_ref } =
            &mut config.authentication.oidc.provider.jwks_source
        else {
            panic!("configured static JWKS source changed kind")
        };
        *document_ref = literal_secret.to_owned();
        let message = config
            .oidc_verifier(&secrets)
            .await
            .map(|_| ())
            .expect_err("a literal credential is not a secret reference")
            .to_string();
        assert!(
            message.contains("authentication.oidc.jwksSource.documentRef")
                && message.contains("secret:env/NAME or secret:file/name"),
            "the failure does not name the field and reference grammar: {message}"
        );
        assert!(
            !message.contains(literal_secret),
            "the failure renders the literal credential: {message}"
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
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let secrets_root = root.path().join("secrets");
        std::fs::create_dir(&secrets_root).unwrap();
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"kind": "static", "documentRef": "secret:file/jwks.json"});
        let config = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap();
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

    #[test]
    fn the_runtime_configuration_is_read_through_the_shared_loader() {
        let error = RuntimeConfig::load("runtime.yaml").unwrap_err();
        assert!(error.to_string().contains("absolute"), "{error}");

        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let mut document = operator_value(&package, "development-loopback");
        document["listener"].as_object_mut().unwrap().remove("bind");
        let error = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap_err();
        assert_eq!(error.path(), "listener");
        assert!(error.to_string().contains("bind"), "{error}");
    }

    #[test]
    fn a_removed_jwks_uri_names_its_replacement() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["jwksUri"] =
            serde_json::json!("https://identity.example.test/jwks");
        let error = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap_err();
        assert_eq!(error.path(), "authentication.oidc.jwksUri");
        assert!(
            error.to_string().contains("authentication.oidc.jwksSource"),
            "{error}"
        );

        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"kind": "uri", "uri": "https://identity.example.test/jwks"});
        let config = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap();
        assert_eq!(
            config.authentication.oidc.provider.jwks_source.uri(),
            Some("https://identity.example.test/jwks")
        );
    }

    #[test]
    fn the_oidc_issuer_and_clients_are_the_shared_blocks() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["authentication"]["oidc"]["issuer"] =
            serde_json::json!("http://identity.example.test");
        let error = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap_err();
        assert_eq!(error.path(), "authentication.oidc.issuer");

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["authentication"]["oidc"]["issuerr"] =
            serde_json::json!("https://identity.example.test");
        let error = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap_err();
        assert!(error.to_string().contains("issuerr"), "{error}");
    }

    #[test]
    fn environment_expressions_substitute_values_but_never_secret_references() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["audience"] =
            serde_json::json!("${CASEWORK_TEST_AUDIENCE:-urn:example:substituted}");
        let config = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap();
        assert_eq!(
            config.authentication.oidc.provider.audience,
            "urn:example:substituted"
        );

        for (pointer, field) in [
            ("/database/runtimeUrlRef", "database.runtimeUrlRef"),
            ("/audit/hashKeyRef", "audit.hashKeyRef"),
        ] {
            let mut document = operator_value(&package, "development-loopback");
            *document.pointer_mut(pointer).unwrap() =
                serde_json::json!("${CASEWORK_TEST_REFERENCE:-secret:env/RUNTIME}");
            let error = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap_err();
            assert!(
                matches!(
                    &error,
                    RuntimeConfigError::Load(load)
                        if load.code() == "runtime_config.substitution_in_reference"
                ),
                "{error}"
            );
            assert_eq!(error.path(), field);
        }
    }

    #[test]
    fn an_authored_project_carrying_an_environment_expression_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package_with_project(
            &package,
            &SOURCE_PROJECT.replace("label: Review", "label: \"${QUEUE_LABEL}\""),
        );
        let operator = write_operator(
            root.path(),
            &operator_value(&package, "development-loopback"),
        );
        let error = RuntimeConfig::load(&operator).unwrap_err();
        let diagnostics = project_refusal(&error);
        assert_eq!(
            diagnostics,
            [(
                "config.substitution-not-allowed".to_owned(),
                "/queues/0/label".to_owned()
            )],
            "{error}"
        );
        assert_eq!(error.path(), "package.root/casework.yaml");
    }

    /// The `code` and `path` of every diagnostic of a refused project.
    fn project_refusal(error: &RuntimeConfigError) -> Vec<(String, String)> {
        let RuntimeConfigError::Project(ConfigLoadError::Refused(report)) = error else {
            panic!("expected a refused project, got {error}");
        };
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect()
    }

    /// A typed field holding an expression would otherwise fail the typed
    /// project read first, with a type error that quotes the expression.
    #[test]
    fn an_environment_expression_in_a_non_string_field_is_the_authored_refusal() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        let project = SOURCE_CONTEXT_REVIEW_PROJECT
            .replace("recoveryDays: 7", "recoveryDays: ${RECOVERY_DAYS}");
        assert_ne!(project, SOURCE_CONTEXT_REVIEW_PROJECT);
        write_package_with_project(&package, &project);
        let operator = write_operator(
            root.path(),
            &operator_value(&package, "development-loopback"),
        );
        let error = RuntimeConfig::load(&operator).unwrap_err();
        assert_eq!(
            project_refusal(&error),
            [(
                "config.substitution-not-allowed".to_owned(),
                "/reviewProducers/0/recoveryDays".to_owned()
            )],
            "{error}"
        );
        let RuntimeConfigError::Project(project) = &error else {
            unreachable!()
        };
        assert!(!project.to_string().contains("RECOVERY_DAYS"), "{project}");
    }

    #[test]
    fn production_names_its_allowed_clients_while_loopback_may_leave_them_empty() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["authentication"]["oidc"]["allowedClients"] = serde_json::json!([]);
        let error = RuntimeConfig::load(write_operator(root.path(), &document)).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::AllowedClientsRequired),
            "{error}"
        );
        assert_eq!(error.path(), "authentication.oidc.allowedClients");
        assert!(
            error.to_string().contains("operator-controlled-upstream"),
            "{error}"
        );

        document["authentication"]["oidc"]["allowedClients"] =
            serde_json::json!(["casework-console"]);
        let config = RuntimeConfig::load(write_operator(root.path(), &document))
            .expect("a named client list is accepted");
        assert_eq!(
            config.authentication.oidc.clients.allowed_clients,
            ["casework-console"]
        );
        assert!(config.task_authority.is_none());

        let config = RuntimeConfig::load(write_operator(
            root.path(),
            &operator_value(&package, "development-loopback"),
        ))
        .expect("development loopback keeps an empty client list");
        assert!(config
            .authentication
            .oidc
            .clients
            .allowed_clients
            .is_empty());
        assert!(config.task_authority.is_none());
    }

    #[test]
    fn static_source_uses_document_ref_camel_case() {
        let source: JwksSource =
            serde_json::from_str(r#"{"kind":"static","documentRef":"secret:file/keys.json"}"#)
                .expect("static source");
        assert!(
            matches!(source,JwksSource::Static{document_ref} if document_ref=="secret:file/keys.json")
        );
    }

    #[test]
    fn human_identity_defaults_to_an_explicit_fail_closed_claim_contract() {
        let oidc: OidcConfig = serde_json::from_value(serde_json::json!({
            "issuer": "https://identity.example.test",
            "audience": "urn:example:casework"
        }))
        .expect("OIDC configuration");
        assert_eq!(
            oidc.human_identity,
            HumanIdentityConfig {
                claim: "registry_actor_kind".to_owned(),
                value: "human".to_owned(),
            }
        );
        assert_eq!(oidc.scope_claim, "registry_scopes");
    }

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

    /// Build a runtime configuration with a static JWKS source (so building the
    /// verifier never performs a real discovery fetch) and return the verifier
    /// configuration it produces, optionally with an authored assertionIssuers
    /// value.
    #[cfg(unix)]
    async fn built_verifier(assertion_issuers: Option<serde_json::Value>) -> TokenVerifierConfig {
        use std::os::unix::fs::PermissionsExt as _;

        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let secrets_root = root.path().join("secrets");
        std::fs::create_dir(&secrets_root).unwrap();
        std::fs::write(
            secrets_root.join("jwks.json"),
            br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(
            secrets_root.join("jwks.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"kind": "static", "documentRef": "secret:file/jwks.json"});
        if let Some(assertion_issuers) = assertion_issuers {
            document["authentication"]["oidc"]["assertionIssuers"] = assertion_issuers;
        }
        let operator = root.path().join("operator.yaml");
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();

        let config = RuntimeConfig::load(&operator).expect("configuration is accepted");
        let secrets = SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            &secrets_root,
        )
        .unwrap();
        config
            .oidc_verifier(&secrets)
            .await
            .expect("the verifier is built")
            .0
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn assertion_issuers_defaults_to_an_empty_map_leaving_the_verifier_with_no_rule() {
        let verifier = built_verifier(None).await;
        assert!(verifier.assertion_issuers.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_configured_assertion_issuers_map_reaches_the_built_verifier() {
        let verifier = built_verifier(Some(serde_json::json!({
            "task-agent": ["https://exchange.example.test"]
        })))
        .await;
        let mut expected = BTreeMap::new();
        expected.insert(
            "task-agent".to_owned(),
            vec!["https://exchange.example.test".to_owned()],
        );
        assert_eq!(verifier.assertion_issuers, expected);
    }

    #[test]
    fn a_duplicate_issuer_within_one_clients_assertion_issuer_list_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            "task-agent": [
                "https://exchange.example.test",
                "https://exchange.example.test"
            ]
        });
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Block(error)) if error.field() == "authentication.oidc.assertionIssuers"
        ));
    }

    #[test]
    fn an_empty_assertion_issuer_string_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            "task-agent": [""]
        });
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Block(error)) if error.field() == "authentication.oidc.assertionIssuers"
        ));
    }

    #[test]
    fn an_empty_assertion_issuer_client_key_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            "": ["https://exchange.example.test"]
        });
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Block(error)) if error.field() == "authentication.oidc.assertionIssuers"
        ));
    }

    #[test]
    fn an_over_long_assertion_issuer_client_key_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        let client = "a".repeat(MAX_ASSERTION_ISSUER_CLIENT_BYTES + 1);
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            client: ["https://exchange.example.test"]
        });
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Block(error)) if error.field() == "authentication.oidc.assertionIssuers"
        ));
    }

    #[test]
    fn an_over_long_assertion_issuer_value_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        let issuer = format!(
            "https://{}.example.test",
            "a".repeat(MAX_ASSERTION_ISSUER_BYTES)
        );
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            "task-agent": [issuer]
        });
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Block(error)) if error.field() == "authentication.oidc.assertionIssuers"
        ));
    }

    #[test]
    fn too_many_assertion_issuer_clients_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        let mut assertion_issuers = serde_json::Map::new();
        for index in 0..=MAX_ASSERTION_ISSUER_CLIENTS {
            assertion_issuers.insert(
                format!("task-agent-{index}"),
                serde_json::json!(["https://exchange.example.test"]),
            );
        }
        document["authentication"]["oidc"]["assertionIssuers"] =
            serde_json::Value::Object(assertion_issuers);
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Block(error)) if error.field() == "authentication.oidc.assertionIssuers"
        ));
    }

    #[test]
    fn too_many_issuers_for_one_assertion_issuer_client_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        let issuers: Vec<String> = (0..=MAX_ASSERTION_ISSUERS_PER_CLIENT)
            .map(|index| format!("https://exchange-{index}.example.test"))
            .collect();
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            "task-agent": issuers
        });
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Block(error)) if error.field() == "authentication.oidc.assertionIssuers"
        ));
    }

    fn packaged_operator(root: &Path, tls: &str) -> (PathBuf, PathBuf, VerifiedPackage) {
        let package = root.join("package");
        std::fs::create_dir(&package).unwrap();
        let verified = write_package(&package);
        let operator = write_operator(root, &operator_value(&package, tls));
        (package, operator, verified)
    }

    #[test]
    fn a_missing_identity_block_is_refused_with_the_key_to_add() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let mut document = operator_value(&package, "operator-controlled-upstream");
        document.as_object_mut().unwrap().remove("identity");
        let operator = write_operator(root.path(), &document);

        let error = RuntimeConfig::load(&operator).expect_err("identity is required");
        assert!(
            matches!(error, RuntimeConfigError::MissingIdentity),
            "{error:?}"
        );
        assert_eq!(error.path(), "identity.databaseId");
        let message = error.to_string();
        assert!(
            message.contains("identity:") && message.contains("databaseId:"),
            "{message}"
        );
    }

    #[test]
    fn an_invalid_database_id_is_refused() {
        let long = "d".repeat(MAX_DATABASE_ID_BYTES + 1);
        for invalid in ["", " casework", "casework ", "case\twork", long.as_str()] {
            let root = canonical_tempdir();
            let package = root.path().join("package");
            std::fs::create_dir(&package).unwrap();
            write_package(&package);
            let mut document = operator_value(&package, "operator-controlled-upstream");
            document["identity"]["databaseId"] = serde_json::json!(invalid);
            let operator = write_operator(root.path(), &document);

            let error = RuntimeConfig::load(&operator).expect_err("invalid databaseId");
            assert!(
                matches!(error, RuntimeConfigError::InvalidDatabaseId),
                "{invalid:?}: {error:?}"
            );
            assert_eq!(error.path(), "identity.databaseId");
        }
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let mut document = operator_value(&package, "operator-controlled-upstream");
        let longest = "d".repeat(MAX_DATABASE_ID_BYTES);
        document["identity"]["databaseId"] = serde_json::json!(longest);
        let operator = write_operator(root.path(), &document);
        let config = RuntimeConfig::load(&operator).expect("the longest id is accepted");
        assert_eq!(config.database_id(), longest);
    }

    #[test]
    fn a_packaged_project_is_verified_against_its_sum_file() {
        let root = canonical_tempdir();
        let (package, operator, verified) =
            packaged_operator(root.path(), "operator-controlled-upstream");
        let config = RuntimeConfig::load(&operator).unwrap();
        assert_eq!(config.package_digest().unwrap(), verified.digest());

        std::fs::write(package.join("sources/professional.json"), b"changed").unwrap();
        let error = RuntimeConfig::load(&operator).expect_err("a changed file is refused");
        assert_eq!(error.path(), "package.root");
        let message = error.to_string();
        assert!(
            message.contains("changed: sources/professional.json"),
            "{message}"
        );
        assert!(message.contains(PACKAGE_COMMAND), "{message}");
    }

    #[test]
    fn final_package_load_binds_captured_policy_and_source_bytes_to_the_verified_digest() {
        for (changed_path, replacement) in [
            ("casework.yaml", b"changed policy\n".as_slice()),
            (
                "sources/professional.json",
                b"{\"changed\":true}\n".as_slice(),
            ),
        ] {
            let root = canonical_tempdir();
            let (package, operator, _) =
                packaged_operator(root.path(), "operator-controlled-upstream");
            let config = RuntimeConfig::load(&operator).expect("the original package loads");

            let error = config
                .load_package_after_verification(|| {
                    std::fs::write(package.join(changed_path), replacement).unwrap();
                })
                .expect_err("bytes replaced after verification are refused");
            assert!(
                matches!(
                    error,
                    RuntimeConfigError::PackageFileChanged { ref path } if path == changed_path
                ),
                "{changed_path}: {error:?}"
            );
        }
    }

    #[test]
    fn final_unpinned_package_load_revalidates_project_bindings_after_replacement() {
        let root = canonical_tempdir();
        let (package, operator, _) = packaged_operator(root.path(), "operator-controlled-upstream");
        let config = RuntimeConfig::load(&operator).expect("package A is valid");

        std::fs::remove_file(package.join(SUM_FILE)).unwrap();
        let replacement =
            SOURCE_PROJECT.replace("principalClaim: sub", "principalClaim: registry_actor_kind");
        std::fs::write(package.join(POLICY_FILE), replacement).unwrap();
        registry_platform_config::write_sum_file(
            &package,
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();

        let error = config
            .load_package()
            .expect_err("package B conflicts with the configured human identity claim");
        assert!(matches!(error, RuntimeConfigError::InvalidOidc));
    }

    #[test]
    fn a_missing_or_extra_package_file_is_refused_by_name() {
        let root = canonical_tempdir();
        let (package, operator, _) = packaged_operator(root.path(), "operator-controlled-upstream");
        std::fs::write(package.join("sources/stale.json"), b"stale").unwrap();
        let message = RuntimeConfig::load(&operator)
            .expect_err("an extra file is refused")
            .to_string();
        assert!(message.contains("extra: sources/stale.json"), "{message}");
        std::fs::remove_file(package.join("sources/stale.json")).unwrap();

        std::fs::remove_file(package.join("sources/professional.json")).unwrap();
        let message = RuntimeConfig::load(&operator)
            .expect_err("a missing file is refused")
            .to_string();
        assert!(
            message.contains("missing: sources/professional.json"),
            "{message}"
        );
    }

    #[test]
    fn a_package_holds_exactly_the_policy_and_its_source_descriptions() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir_all(package.join("sources")).unwrap();
        std::fs::write(package.join("casework.yaml"), SOURCE_PROJECT).unwrap();
        std::fs::write(
            package.join("sources/professional.json"),
            SOURCE_DESCRIPTION,
        )
        .unwrap();
        std::fs::write(package.join("notes.txt"), b"not an input").unwrap();
        registry_platform_config::write_sum_file(
            &package,
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();
        let operator = write_operator(
            root.path(),
            &operator_value(&package, "operator-controlled-upstream"),
        );
        let error = RuntimeConfig::load(&operator).expect_err("a stray input is refused");
        assert!(matches!(
            &error,
            RuntimeConfigError::PackageContents { missing, extra }
                if missing.is_empty() && extra == &["notes.txt".to_owned()]
        ));
        assert!(error.to_string().contains("extra: notes.txt"), "{error}");
    }

    #[test]
    fn a_retired_package_manifest_is_refused_with_its_replacement() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        std::fs::create_dir_all(package.join("sources")).unwrap();
        std::fs::write(package.join("casework.yaml"), SOURCE_PROJECT).unwrap();
        std::fs::write(
            package.join("sources/professional.json"),
            SOURCE_DESCRIPTION,
        )
        .unwrap();
        std::fs::write(package.join(RETIRED_PACKAGE_MANIFEST_FILE), b"{}").unwrap();
        let operator = write_operator(
            root.path(),
            &operator_value(&package, "development-loopback"),
        );
        let error = RuntimeConfig::load(&operator).expect_err("the retired manifest is refused");
        assert!(matches!(error, RuntimeConfigError::RetiredPackageManifest));
        assert!(error.to_string().contains(PACKAGE_COMMAND), "{error}");
    }

    #[test]
    fn every_listener_mode_verifies_the_package_without_a_pin() {
        for tls in ["operator-controlled-upstream", "development-loopback"] {
            let root = canonical_tempdir();
            let (package, operator, verified) = packaged_operator(root.path(), tls);
            let config = RuntimeConfig::load(&operator).expect("the package is admitted");
            assert!(config.package.expected_digest.is_none());
            assert_eq!(config.package_digest().unwrap(), verified.digest());

            let refusal = |expected: &str| {
                let error = RuntimeConfig::load(&operator).expect_err(expected);
                assert_eq!(error.path(), "package.root", "{tls}: {error}");
                let message = error.to_string();
                assert!(message.contains(expected), "{tls}: {message}");
                assert!(message.contains(PACKAGE_COMMAND), "{tls}: {message}");
            };

            std::fs::write(
                package.join("casework.yaml"),
                format!("{SOURCE_PROJECT}\n# changed\n"),
            )
            .unwrap();
            refusal("changed: casework.yaml");
            std::fs::write(package.join("casework.yaml"), SOURCE_PROJECT).unwrap();

            std::fs::write(package.join("sources/stale.json"), b"stale").unwrap();
            refusal("extra: sources/stale.json");
            std::fs::remove_file(package.join("sources/stale.json")).unwrap();

            std::fs::remove_file(package.join("sources/professional.json")).unwrap();
            refusal("missing: sources/professional.json");
            std::fs::write(
                package.join("sources/professional.json"),
                SOURCE_DESCRIPTION,
            )
            .unwrap();
            assert!(RuntimeConfig::load(&operator).is_ok(), "{tls}");

            std::fs::remove_file(package.join(SUM_FILE)).unwrap();
            let error = RuntimeConfig::load(&operator).expect_err("an authored project is refused");
            assert!(matches!(
                &error,
                RuntimeConfigError::Package(error)
                    if matches!(error.kind(), PackageErrorKind::SumFileMissing)
            ));
            assert!(error.to_string().contains("has no SHA256SUMS"), "{error}");
            assert!(error.to_string().contains(PACKAGE_COMMAND), "{error}");
        }
    }

    #[test]
    fn a_package_digest_mismatch_is_refused_in_the_shared_shape() {
        let root = canonical_tempdir();
        let (package, operator, verified) =
            packaged_operator(root.path(), "operator-controlled-upstream");
        let write = |expected: &str| {
            let mut document = operator_value(&package, "operator-controlled-upstream");
            document["package"]["expectedDigest"] = serde_json::json!(expected);
            write_operator(root.path(), &document);
        };

        write(verified.digest());
        let config = RuntimeConfig::load(&operator).expect("the pinned package is admitted");
        assert_eq!(
            config.package.expected_digest.as_deref(),
            Some(verified.digest())
        );

        let pinned = format!("sha256:{}", "0".repeat(64));
        write(&pinned);
        let error = RuntimeConfig::load(&operator).expect_err("a different package is refused");
        assert!(matches!(
            &error,
            RuntimeConfigError::PackageDigest(PackageDigestMismatch { expected, found })
                if expected == &pinned && found == verified.digest()
        ));
        assert_eq!(error.path(), "package.expectedDigest");
        assert_eq!(
            error.to_string(),
            PackageDigestMismatch {
                expected: pinned,
                found: verified.digest().to_owned(),
            }
            .to_string()
        );
    }

    #[test]
    fn an_expected_digest_refuses_an_unpackaged_project() {
        let root = canonical_tempdir();
        let (package, _, verified) = packaged_operator(root.path(), "development-loopback");
        std::fs::remove_file(package.join(SUM_FILE)).unwrap();
        let mut document = operator_value(&package, "development-loopback");
        document["package"]["expectedDigest"] = serde_json::json!(verified.digest());
        let operator = write_operator(root.path(), &document);

        let error = RuntimeConfig::load(&operator).expect_err("an unpackaged project is refused");
        assert!(matches!(
            &error,
            RuntimeConfigError::Package(error)
                if matches!(error.kind(), PackageErrorKind::SumFileMissing)
        ));
        assert_eq!(error.path(), "package.root");
    }

    #[test]
    fn a_malformed_expected_digest_is_refused() {
        let root = canonical_tempdir();
        let (package, _, verified) = packaged_operator(root.path(), "operator-controlled-upstream");
        for malformed in [
            String::new(),
            verified.digest().to_uppercase(),
            verified.digest().trim_start_matches("sha256:").to_owned(),
            format!("{}0", verified.digest()),
            format!("sha512:{}", "0".repeat(64)),
        ] {
            let mut document = operator_value(&package, "operator-controlled-upstream");
            document["package"]["expectedDigest"] = serde_json::json!(malformed);
            let operator = write_operator(root.path(), &document);
            let error = RuntimeConfig::load(&operator).expect_err("a malformed digest is refused");
            assert!(
                matches!(error, RuntimeConfigError::Block(_)),
                "{malformed}: {error:?}"
            );
            assert_eq!(error.path(), "package.expectedDigest");
        }
    }

    #[test]
    fn the_retired_expected_policy_digest_key_names_its_replacement() {
        let root = canonical_tempdir();
        let (package, _, verified) = packaged_operator(root.path(), "operator-controlled-upstream");
        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["package"]["expectedPolicyDigest"] = serde_json::json!(verified.digest());
        let operator = write_operator(root.path(), &document);
        let message = RuntimeConfig::load(&operator)
            .expect_err("the retired key is refused")
            .to_string();
        assert!(
            message.contains("/package/expectedPolicyDigest"),
            "{message}"
        );
        assert!(message.contains("package.expectedDigest"), "{message}");
    }

    #[test]
    fn a_stranded_work_acknowledgement_names_one_package_digest() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        let manifest = write_package(&package);
        let operator = root.path().join("operator.yaml");
        let write = |acknowledged: &str| {
            let mut document = operator_value(&package, "operator-controlled-upstream");
            document["package"]["acknowledgeStrandedWork"] = serde_json::json!(acknowledged);
            std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        };

        write(manifest.digest());
        let config = RuntimeConfig::load(&operator).expect("a digest acknowledgement loads");
        assert_eq!(
            config.package.acknowledge_stranded_work.as_deref(),
            Some(manifest.digest())
        );

        for malformed in ["yes", "sha256:ABC"] {
            write(malformed);
            let error = RuntimeConfig::load(&operator).expect_err("a malformed digest is refused");
            assert!(
                matches!(
                    error,
                    RuntimeConfigError::InvalidStrandedWorkAcknowledgement
                ),
                "{malformed}: {error:?}"
            );
            assert_eq!(error.path(), "package.acknowledgeStrandedWork");
        }
    }

    #[test]
    fn source_context_review_namespaces_require_activated_adapters() {
        let root = canonical_tempdir();
        let package = root.path().join("source-context");
        std::fs::create_dir(&package).unwrap();
        write_package_with_project(&package, SOURCE_CONTEXT_REVIEW_PROJECT);
        let runtime = root.path().join("source-context.yaml");
        std::fs::write(
            &runtime,
            operator_document(&package, "operator-controlled-upstream"),
        )
        .unwrap();
        RuntimeConfig::load(&runtime).expect("the source namespace has an activated adapter");

        let canary = "UNACTIVATED_SOURCE_NAMESPACE_CANARY";
        let project =
            SOURCE_CONTEXT_REVIEW_PROJECT.replace("[professional]", &format!("[{canary}]"));
        let package = root.path().join("missing-source-context-adapter");
        std::fs::create_dir(&package).unwrap();
        write_package_with_project(&package, &project);
        let runtime = root.path().join("missing-source-context-adapter.yaml");
        std::fs::write(
            &runtime,
            operator_document(&package, "operator-controlled-upstream"),
        )
        .unwrap();
        let error = RuntimeConfig::load(&runtime).expect_err("the absent adapter is refused");
        assert!(matches!(
            &error,
            RuntimeConfigError::InactiveReviewSourceNamespace
        ));
        assert_eq!(error.path(), "package.root/casework.yaml");
        assert!(!error.to_string().contains(canary));

        let project = project.replace("contextStrategy: source", "contextStrategy: submitted");
        let package = root.path().join("submitted-context");
        std::fs::create_dir(&package).unwrap();
        write_package_with_project(&package, &project);
        let runtime = root.path().join("submitted-context.yaml");
        std::fs::write(
            &runtime,
            operator_document(&package, "operator-controlled-upstream"),
        )
        .unwrap();
        RuntimeConfig::load(&runtime)
            .expect("submitted context does not require a source adapter for its namespace");
    }

    #[test]
    fn retained_completion_destinations_may_remain_configured_after_policy_removal() {
        let root = canonical_tempdir();
        let package = root.path().join("source-context");
        std::fs::create_dir(&package).unwrap();
        write_package_with_project(&package, SOURCE_CONTEXT_REVIEW_PROJECT);
        let runtime = root.path().join("source-context.yaml");
        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["reviewCompletionDestinations"] = serde_json::json!({
            "retained-destination": {
                "url": "https://completion.example.test/v1/reviews",
                "bearerTokenRef": "secret:file/completion-token"
            }
        });
        std::fs::write(&runtime, serde_norway::to_string(&document).unwrap()).unwrap();
        RuntimeConfig::load(&runtime)
            .expect("an undeclared retained destination stays operable during drain");
    }

    #[test]
    fn a_completion_destination_names_a_safe_header_for_its_secret() {
        let root = canonical_tempdir();
        let package = root.path().join("source-context");
        std::fs::create_dir(&package).unwrap();
        write_package_with_project(&package, SOURCE_CONTEXT_REVIEW_PROJECT);
        let runtime = root.path().join("completion-auth.yaml");
        let load = |destination: serde_json::Value| {
            let mut document = operator_value(&package, "operator-controlled-upstream");
            document["reviewCompletionDestinations"] =
                serde_json::json!({ "receiver": destination });
            std::fs::write(&runtime, serde_norway::to_string(&document).unwrap()).unwrap();
            RuntimeConfig::load(&runtime)
        };
        let url = "https://completion.example.test/v1/reviews";

        let custom = load(serde_json::json!({
            "url": url,
            "auth": {"header": "X-Api-Key", "secretRef": "secret:file/completion-key"}
        }))
        .expect("a custom header is accepted");
        let auth = custom.review_completion_destinations["receiver"]
            .auth
            .as_ref()
            .expect("configured auth");
        assert_eq!(auth.header.as_deref(), Some("X-Api-Key"));
        assert_eq!(
            custom.review_completion_destinations["receiver"].secret_header(),
            Some("X-Api-Key")
        );
        assert_eq!(
            custom.review_completion_destinations["receiver"].secret_ref(),
            Some("secret:file/completion-key")
        );
        let defaulted = load(serde_json::json!({
            "url": url,
            "auth": {"secretRef": "secret:file/completion-key"}
        }))
        .expect("auth without a header keeps the bearer default");
        assert_eq!(
            defaulted.review_completion_destinations["receiver"].secret_ref(),
            Some("secret:file/completion-key")
        );
        let shorthand = load(serde_json::json!({
            "url": url,
            "bearerTokenRef": "secret:file/completion-token"
        }))
        .expect("bearerTokenRef stays the shorthand for the default");
        assert_eq!(
            shorthand.review_completion_destinations["receiver"].secret_ref(),
            Some("secret:file/completion-token")
        );
        // `null` is never a value (CFG-EMPTY-1): absence is spelled by
        // leaving the key out.
        let null_shorthand = load(serde_json::json!({
            "url": url,
            "bearerTokenRef": null,
            "auth": {"secretRef": "secret:file/completion-key"}
        }))
        .expect_err("a null bearerTokenRef is refused")
        .to_string();
        assert!(
            null_shorthand.contains("error[config.null-value]"),
            "{null_shorthand}"
        );
        assert!(load(serde_json::json!({"url": url, "bearerTokenRef": null})).is_err());

        for header in [
            "Authorization",
            "proxy-authorization",
            "Host",
            "Content-Length",
            "Content-Type",
            "Transfer-Encoding",
            "Connection",
            "Keep-Alive",
            "TE",
            "Trailer",
            "Upgrade",
            "Cookie",
            "Idempotency-Key",
            "Registry-Recipient-Binding",
            "registry-anything",
            "X-Forwarded-For",
            "Traceparent",
            "",
            "x api key",
            "x-api-key\r\nhost",
            &"x".repeat(65),
        ] {
            let refused = load(serde_json::json!({
                "url": url,
                "auth": {"header": header, "secretRef": "secret:file/completion-key"}
            }))
            .expect_err(header);
            assert_eq!(
                refused.path(),
                "reviewCompletionDestinations.receiver.auth.header",
                "{header}"
            );
        }
        for destination in [
            serde_json::json!({"url": url}),
            serde_json::json!({
                "url": url,
                "bearerTokenRef": "secret:file/completion-token",
                "auth": {"header": "x-api-key", "secretRef": "secret:file/completion-key"}
            }),
        ] {
            let refused = load(destination).expect_err("exactly one credential");
            assert_eq!(refused.path(), "reviewCompletionDestinations.receiver.auth");
        }
        let unknown = load(serde_json::json!({
            "url": url,
            "auth": {"header": "x-api-key", "secretRef": "secret:file/completion-key", "scheme": "Basic"}
        }))
        .expect_err("closed auth object");
        assert!(matches!(unknown, RuntimeConfigError::Load(_)));
    }

    #[test]
    fn the_optional_metrics_listener_is_absent_by_default_and_stays_operator_private() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let load = |metrics: Option<serde_json::Value>, listener: &str| {
            let mut document = operator_value(&package, "operator-controlled-upstream");
            document["listener"]["bind"] = serde_json::json!(listener);
            document["listener"]["networkExposure"] = serde_json::json!("container-private");
            if let Some(metrics) = metrics {
                document["metricsListener"] = metrics;
            }
            std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
            RuntimeConfig::load(&operator)
        };

        assert!(load(None, "127.0.0.1:8100")
            .unwrap()
            .metrics_listener
            .is_none());
        for accepted in [
            "127.0.0.1:9100",
            "10.0.0.5:9100",
            "[fd00::1]:9100",
            "[::1]:9100",
        ] {
            let config = load(
                Some(serde_json::json!({"bind": accepted})),
                "127.0.0.1:8100",
            )
            .unwrap_or_else(|error| panic!("{accepted}: {error}"));
            assert_eq!(
                config.metrics_listener.expect("metrics listener").bind,
                accepted.parse().unwrap()
            );
        }
        for (refused, listener) in [
            ("0.0.0.0:9100", "127.0.0.1:8100"),
            ("[::]:9100", "127.0.0.1:8100"),
            ("203.0.113.9:9100", "127.0.0.1:8100"),
            ("127.0.0.1:0", "127.0.0.1:8100"),
            ("127.0.0.1:8100", "127.0.0.1:8100"),
            ("10.0.0.5:8100", "0.0.0.0:8100"),
            ("[fd00::1]:8100", "[::]:8100"),
            ("10.0.0.5:8100", "[::]:8100"),
        ] {
            let error =
                load(Some(serde_json::json!({"bind": refused})), listener).expect_err(refused);
            assert!(
                matches!(error, RuntimeConfigError::InvalidMetricsListener),
                "{refused} beside {listener}: {error}"
            );
            assert_eq!(error.path(), "metricsListener");
        }
        assert!(load(
            Some(serde_json::json!({"bind": "10.0.0.5:8100"})),
            "[fd00::1]:8100"
        )
        .is_ok());
        assert!(matches!(
            load(
                Some(serde_json::json!({"bind": "127.0.0.1:9100", "path": "/metrics"})),
                "127.0.0.1:8100"
            ),
            Err(RuntimeConfigError::Load(_))
        ));
    }

    #[test]
    fn runtime_envelope_listener_and_operated_paths_are_strict() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let valid = operator_document(&package, "operator-controlled-upstream");
        let omitted_bind = valid.replace("  bind: 127.0.0.1:8100\n", "");
        std::fs::write(&operator, &omitted_bind).unwrap();
        assert_eq!(
            RuntimeConfig::load(&operator).unwrap_err().path(),
            "listener"
        );

        assert!(matches!(
            RuntimeConfig::load("runtime.yaml"),
            Err(RuntimeConfigError::Load(load)) if load.kind() == RuntimeConfigErrorKind::Path
        ));

        std::fs::write(
            &operator,
            valid.replace(RUNTIME_CONFIG_API_VERSION, "registry.example/unsupported"),
        )
        .unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Load(load)) if load.kind() == RuntimeConfigErrorKind::Envelope
        ));

        std::fs::write(
            &operator,
            valid.replace("  tlsTermination: operator-controlled-upstream\n", ""),
        )
        .unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Load(_))
        ));
    }

    #[test]
    fn removed_runtime_principal_claim_names_the_authored_replacement() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let document = operator_document(&package, "operator-controlled-upstream");
        let document = document.replace(
            "    audience: urn:example:casework\n",
            "    audience: urn:example:casework\n    principalClaim: sub\n",
        );
        std::fs::write(&operator, document).unwrap();
        let error = RuntimeConfig::load(&operator).unwrap_err();
        assert!(matches!(
            &error,
            RuntimeConfigError::Load(load) if load.kind() == RuntimeConfigErrorKind::RemovedKey
        ));
        assert_eq!(error.path(), "authentication.oidc.principalClaim");
        assert!(error
            .to_string()
            .contains("accessProfiles[].principalClaim"));
    }

    /// Load the operator fixture with one member of its only source binding
    /// replaced, and return the refusal. Each binding rule is refused at load
    /// with its own key path and reason, never the value that broke it.
    fn source_binding_refusal(member: &str, value: serde_json::Value) -> RuntimeConfigError {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let mut document = operator_value(&package, "development-loopback");
        document["sources"]["professional"][member] = value;
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        RuntimeConfig::load(&operator).unwrap_err()
    }

    fn assert_source_binding_rule(
        error: &RuntimeConfigError,
        member: &str,
        reason_names: &[&str],
        withheld: &[&str],
    ) {
        let expected = format!("sources.professional.{member}");
        assert!(
            matches!(
                error,
                RuntimeConfigError::InvalidSourceBinding { path, .. } if *path == expected
            ),
            "the refusal does not name {expected}: {error:?}"
        );
        assert_eq!(error.path(), expected);
        let message = error.to_string();
        assert!(
            !message.contains("accepted range"),
            "the refusal collapses to the generic sentence: {message}"
        );
        for name in reason_names {
            assert!(
                message.contains(name),
                "the refusal does not state {name:?}: {message}"
            );
        }
        for value in withheld {
            assert!(
                !message.contains(value),
                "the refusal echoes the configured value {value:?}: {message}"
            );
        }
    }

    #[test]
    fn an_out_of_range_source_binding_interval_is_refused_at_load() {
        for (interval, withheld) in [(999, "999"), (3_600_001, "3600001")] {
            let error = source_binding_refusal(
                "reconciliationIntervalMilliseconds",
                serde_json::json!(interval),
            );
            assert_source_binding_rule(
                &error,
                "reconciliationIntervalMilliseconds",
                &["reconciliationIntervalMilliseconds", "1000", "3600000"],
                &[withheld],
            );
        }
    }

    #[test]
    fn a_request_timeout_shorter_than_the_connect_timeout_names_that_rule() {
        let error = source_binding_refusal("requestTimeoutMilliseconds", serde_json::json!(9_000));
        assert_source_binding_rule(
            &error,
            "requestTimeoutMilliseconds",
            &["requestTimeoutMilliseconds", "connectTimeoutMilliseconds"],
            &["9000"],
        );
    }

    #[test]
    fn an_invalid_reader_profile_names_that_rule() {
        let error = source_binding_refusal("readerProfile", serde_json::json!(" casework-reader"));
        assert_source_binding_rule(
            &error,
            "readerProfile",
            &["readerProfile", "512"],
            &["casework-reader"],
        );
        let error = source_binding_refusal("readerProfile", serde_json::json!("r".repeat(513)));
        assert_source_binding_rule(&error, "readerProfile", &["readerProfile"], &["rrrr"]);
    }

    #[test]
    fn a_zero_connect_timeout_names_that_rule() {
        let error = source_binding_refusal("connectTimeoutMilliseconds", serde_json::json!(0));
        assert_source_binding_rule(
            &error,
            "connectTimeoutMilliseconds",
            &["connectTimeoutMilliseconds", "greater than zero"],
            &[],
        );
    }

    #[test]
    fn a_zero_request_timeout_names_that_rule() {
        let error = source_binding_refusal("requestTimeoutMilliseconds", serde_json::json!(0));
        assert_source_binding_rule(
            &error,
            "requestTimeoutMilliseconds",
            &["requestTimeoutMilliseconds", "greater than zero"],
            &[],
        );
    }

    #[test]
    fn a_request_timeout_above_the_maximum_names_that_rule() {
        let error =
            source_binding_refusal("requestTimeoutMilliseconds", serde_json::json!(300_001));
        assert_source_binding_rule(
            &error,
            "requestTimeoutMilliseconds",
            &["requestTimeoutMilliseconds", "at most 300000"],
            &["300001"],
        );
    }

    #[test]
    fn a_malformed_event_source_names_that_rule() {
        let error = source_binding_refusal(
            "eventSource",
            serde_json::json!("urn:registrystack:registry:professional:pilot"),
        );
        assert_source_binding_rule(
            &error,
            "eventSource",
            &[
                "eventSource",
                "urn:registrystack:registry:<package>:instance:<instance>",
            ],
            &["professional:pilot"],
        );
    }

    #[test]
    fn an_invalid_client_assertion_audience_names_that_rule() {
        let error = source_binding_refusal(
            "clientAssertionAudience",
            serde_json::json!("https://identity.example.test/#assertion"),
        );
        assert_source_binding_rule(
            &error,
            "clientAssertionAudience",
            &["clientAssertionAudience", "absolute URI"],
            &["identity.example.test/#assertion"],
        );
    }

    #[test]
    fn an_invalid_resource_names_that_rule() {
        let error = source_binding_refusal("resource", serde_json::json!(" urn:breg:professional"));
        assert_source_binding_rule(
            &error,
            "resource",
            &["resource", "absolute URI"],
            &["urn:breg:professional"],
        );
    }

    #[test]
    fn an_empty_scope_list_names_that_rule() {
        let error = source_binding_refusal("scopes", serde_json::json!([]));
        assert_source_binding_rule(&error, "scopes", &["scopes", "at least one"], &[]);
    }

    #[test]
    fn too_many_scopes_names_that_rule() {
        let scopes = (0..33)
            .map(|index| format!("casework:scope-{index}"))
            .collect::<Vec<_>>();
        let error = source_binding_refusal("scopes", serde_json::json!(scopes));
        assert_source_binding_rule(
            &error,
            "scopes",
            &["scopes", "at most 32"],
            &["casework:scope-"],
        );
    }

    #[test]
    fn a_repeated_scope_names_that_rule() {
        let error = source_binding_refusal(
            "scopes",
            serde_json::json!(["casework:source-reader", "casework:source-reader"]),
        );
        assert_source_binding_rule(
            &error,
            "scopes",
            &["scopes", "repeat"],
            &["casework:source-reader"],
        );
    }

    #[test]
    fn a_scope_that_is_not_a_scope_token_names_that_rule() {
        let error = source_binding_refusal("scopes", serde_json::json!(["casework source-reader"]));
        assert_source_binding_rule(
            &error,
            "scopes",
            &["scopes", "scope-token"],
            &["casework source-reader"],
        );
    }

    #[test]
    fn a_scope_longer_than_the_maximum_names_that_rule() {
        let error = source_binding_refusal("scopes", serde_json::json!(["s".repeat(257)]));
        assert_source_binding_rule(&error, "scopes", &["scopes", "256 bytes"], &["ssss"]);
    }

    #[test]
    fn environment_secret_references_require_the_explicit_provider() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let document = operator_document(&package, "operator-controlled-upstream")
            .replace("  environment: {}\n", "");
        std::fs::write(&operator, document).unwrap();
        let error = RuntimeConfig::load(&operator).unwrap_err();
        assert!(matches!(
            &error,
            RuntimeConfigError::Block(block)
                if block.kind() == registry_platform_config::ConfigBlockErrorKind::SecretProviderDisabled
        ));
        assert_eq!(error.path(), "database.runtimeUrlRef");
    }

    /// RFC 9068 gives the access token one media type spelled two ways,
    /// `at+jwt` and `application/at+jwt`, and requires a resource server to
    /// accept that pair and refuse every other `typ`. A plain `JWT` is not
    /// that type: an ID token, a UserInfo JWT, or any other JWT this issuer
    /// mints for this audience would otherwise be admitted as a Casework
    /// access token and act with the scopes it carries.
    #[test]
    fn the_verifier_admits_only_the_rfc_9068_access_token_type() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let runtime = root.path().join("runtime.yaml");
        std::fs::write(
            &runtime,
            operator_document(&package, "operator-controlled-upstream"),
        )
        .unwrap();
        let profile = RuntimeConfig::load(&runtime).unwrap().verifier_profile();
        assert!(
            is_access_token_typ_pair(&profile.allowed_typ),
            "the verifier admits {:?}",
            profile.allowed_typ
        );
    }

    /// `serde_path_to_error` renders a refusal it never attributed to a
    /// member as `.`, which names nothing an operator can look up. A document
    /// refused whole is reported at `/`, the root every other whole-document
    /// refusal here already names.
    #[test]
    fn a_document_refused_whole_is_reported_at_its_root() {
        let root = canonical_tempdir();
        let runtime = root.path().join("runtime.yaml");
        std::fs::write(&runtime, "a scalar, not a runtime configuration\n").unwrap();
        let error = RuntimeConfig::load(&runtime).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Load(_)));
        assert_eq!(error.path(), "/");
    }

    #[test]
    fn typed_parse_path_does_not_echo_the_rejected_value() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let runtime = root.path().join("runtime.yaml");
        let canary = "DO_NOT_DISCLOSE_RUNTIME_VALUE";
        let document = operator_document(&package, "operator-controlled-upstream").replace(
            "  migrationUrlRef: secret:env/MIGRATION\n",
            &format!("  migrationUrlRef: secret:env/MIGRATION\n  testOnlyPlaintext: {canary}\n"),
        );
        std::fs::write(&runtime, document).unwrap();
        let error = RuntimeConfig::load(&runtime).unwrap_err();
        assert_eq!(error.path(), "database.testOnlyPlaintext");
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn startup_redecodes_packaged_source_metadata_instead_of_trusting_its_hash() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir_all(package.join("sources")).unwrap();
        std::fs::write(package.join("casework.yaml"), SOURCE_PROJECT).unwrap();
        std::fs::write(package.join("sources/professional.json"), b"{}\n").unwrap();
        registry_platform_config::write_sum_file(
            &package,
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();
        let operator = root.path().join("operator.yaml");
        std::fs::write(
            &operator,
            operator_document(&package, "operator-controlled-upstream"),
        )
        .unwrap();
        assert!(matches!(
            RuntimeConfig::load(operator),
            Err(RuntimeConfigError::SourceDescription)
        ));
    }

    #[test]
    fn listener_requires_a_private_address_or_explicit_container_network() {
        let valid = |bind: &str, exposure, tls_termination| {
            ListenerConfig {
                bind: bind.parse().expect("listener address"),
                tls_termination,
                network_exposure: exposure,
            }
            .is_valid()
        };
        let upstream = TlsTermination::OperatorControlledUpstream;
        let loopback = TlsTermination::DevelopmentLoopback;
        let private = ListenerNetworkExposure::PrivateAddress;
        let container = ListenerNetworkExposure::ContainerPrivate;

        assert!(valid("127.0.0.1:8100", private, upstream));
        assert!(valid("10.20.30.40:8100", private, upstream));
        assert!(!valid("0.0.0.0:8100", private, upstream));
        assert!(valid("[::]:8100", container, upstream));
        assert!(!valid("203.0.113.10:8100", container, upstream));
        assert!(valid("127.0.0.1:8100", private, loopback));
        assert!(!valid("10.20.30.40:8100", private, loopback));
        assert!(!valid("0.0.0.0:8100", container, loopback));
    }
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error(transparent)]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    #[error(transparent)]
    Block(#[from] ConfigBlockError),
    #[error("unsupported Casework runtime apiVersion; expected registry.registrystack.org/casework-runtime/v1alpha1")]
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
        "the package at package.root must hold exactly casework.yaml and the source descriptions it names{}{}; rebuild it with `caseworkctl package`",
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
    #[error(
        "package.root holds casework.package.json, which Casework no longer reads; rebuild the package with `caseworkctl package`, which writes SHA256SUMS"
    )]
    RetiredPackageManifest,
    #[error(
        "package.acknowledgeStrandedWork must be sha256: followed by 64 lowercase hexadecimal digits"
    )]
    InvalidStrandedWorkAcknowledgement,
    #[error("an imported source description does not match the exact configured source policy")]
    SourceDescription,
    #[error("the Casework runtime configuration is invalid")]
    Invalid,
    #[error("listener is not valid for its declared TLS termination and network exposure")]
    InvalidListener,
    #[error(
        "metricsListener.bind must be a loopback or private address with a nonzero port that the API listener does not also occupy"
    )]
    InvalidMetricsListener,
    #[error("authentication.oidc is invalid or conflicts with accessProfiles[].principalClaim")]
    InvalidOidc,
    #[error(
        "authentication.oidc.allowedClients must name every client the deployment admits under operator-controlled-upstream; an empty list admits every client the issuer verifies"
    )]
    AllowedClientsRequired,
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error("{0}")]
    InvalidAuditDestination(#[source] AuditDestinationError),
    #[error("sources must exactly match the source ids declared by package.root/casework.yaml")]
    InvalidSourceBindings,
    #[error(
        "each source namespace admitted for source-context review work must have an activated source adapter"
    )]
    InactiveReviewSourceNamespace,
    #[error("{path} is not valid in a Casework source binding: {reason}")]
    InvalidSourceBinding { path: String, reason: &'static str },
    #[error(
        "{path} must name exactly one completion secret, in a header the runtime does not reserve"
    )]
    InvalidReviewCompletionAuth { path: String },
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
            Self::InvalidApiVersion => "apiVersion",
            Self::InvalidKind => "kind",
            Self::MissingIdentity | Self::InvalidDatabaseId => "identity.databaseId",
            Self::RelativeOperatedPath(path) => path,
            Self::InvalidReviewCompletionAuth { path } => path,
            Self::InvalidSourceBinding { path, .. } => path,
            Self::InvalidOidc | Self::Oidc => "authentication.oidc",
            Self::AllowedClientsRequired => "authentication.oidc.allowedClients",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener",
            Self::InvalidMetricsListener => "metricsListener",
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
            Self::InvalidSourceBindings | Self::SourceDescription => "sources",
            Self::InactiveReviewSourceNamespace => "package.root/casework.yaml",
            Self::Project(_) => "package.root/casework.yaml",
            Self::PolicyUnreadable => "package.root/casework.yaml",
            Self::Package(_)
            | Self::PackageContents { .. }
            | Self::PackageFileChanged { .. }
            | Self::RetiredPackageManifest => "package.root",
            Self::PackageDigest(_) => "package.expectedDigest",
            Self::InvalidStrandedWorkAcknowledgement => "package.acknowledgeStrandedWork",
            Self::Invalid => "/",
        }
    }
}
