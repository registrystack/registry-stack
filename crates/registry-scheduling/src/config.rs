// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document and the policy package
//! identity it verifies.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::Algorithm;
use registry_platform_config::{
    SecretError, SecretProvider, SecretReference, SecretResolver, MAX_SECRET_BYTES,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
    TokenVerifierConfig,
};
use registry_scheduling_core::{
    parse_policy_yaml, SchedulingPolicy, AUTHORED_POLICY_FILE, SCHEDULING_PACKAGE_MANIFEST_FILE,
    SCHEDULING_POLICY_API_VERSION, SCHEDULING_POLICY_KIND, SCHEDULING_RUNTIME_API_VERSION,
    SCHEDULING_RUNTIME_KIND,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Explain one refused secret reference without disclosing what it protects.
///
/// A startup refusal reaches an operator as a single line, and the resolver
/// reports only which rule broke. A valid reference is safe and useful to name,
/// but invalid operator-authored text might itself be a literal credential, so
/// only its field is named. The resolved bytes and opened path never appear.
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

const MAXIMUM_POLICY_FILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_PACKAGE_MANIFEST_BYTES: usize = 1024 * 1024;

/// The default number of days a stored idempotency receipt is replayable
/// before the retention sweep erases it. The default is a floor, not a
/// recommendation: a jurisdiction's retention schedule approves the deployed
/// value, and the deployed value is what the audit journal records.
pub const DEFAULT_ATTEMPT_RECEIPT_DAYS: u16 = 7;

/// The operator runtime configuration document.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub package: RuntimePackageConfig,
    pub listener: ListenerConfig,
    pub secret_providers: SecretProvidersConfig,
    pub database: DatabaseConfig,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub destinations: DestinationsConfig,
    pub retention: RetentionConfig,
}

/// The root of an authored scheduling project, holding `scheduling.yaml` and
/// its optional package manifest.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePackageConfig {
    pub root: PathBuf,
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
    "127.0.0.1:8105"
        .parse()
        .expect("valid Scheduling listener default")
}

/// Declares the trusted transport boundary for the runtime's plaintext HTTP
/// listener. Production listeners require operator-controlled upstream TLS
/// termination; direct plaintext is limited to the explicit loopback-only
/// development mode.
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
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub oidc: OidcConfig,
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
pub struct OidcConfig {
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks_source: OidcJwksSource,
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

/// Where due reminder intents are dispatched. An absent reminders destination
/// is a supported deployment: intents are written and stay local, so an
/// operator can adopt the product before wiring a notification bus.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationsConfig {
    #[serde(default)]
    pub reminders: Option<ReminderDestinationConfig>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderDestinationConfig {
    pub url: String,
    #[serde(default)]
    pub bearer_token_ref: Option<String>,
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
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            attempt_receipt_days: DEFAULT_ATTEMPT_RECEIPT_DAYS,
        }
    }
}

fn default_attempt_receipt_days() -> u16 {
    DEFAULT_ATTEMPT_RECEIPT_DAYS
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
            sha256: sha256_bytes(bytes),
            bytes: u64::try_from(bytes.len()).map_err(|_| PolicyPackageError::Invalid)?,
        }];
        Ok(Self {
            api_version: SCHEDULING_POLICY_API_VERSION.to_owned(),
            kind: SCHEDULING_POLICY_KIND.to_owned(),
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
        "apiVersion": SCHEDULING_POLICY_API_VERSION,
        "kind": SCHEDULING_POLICY_KIND,
        "files": files,
    });
    let canonical = registry_platform_canonical_json::canonicalize_json(&identity)
        .map_err(|_| PolicyPackageError::Invalid)?;
    Ok(sha256_bytes(&canonical))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

impl RuntimeConfig {
    /// Load and validate the operator document, reading the authored policy
    /// beside it. The bytes never re-enter a parser after startup.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        if !path.as_ref().is_absolute() {
            return Err(RuntimeConfigError::RelativeRuntimePath);
        }
        let bytes = std::fs::read(path.as_ref()).map_err(RuntimeConfigError::Read)?;
        let deserializer = serde_norway::Deserializer::from_slice(&bytes);
        let config: Self = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let path = error.path().to_string();
            RuntimeConfigError::Parse {
                path: if path.is_empty() {
                    "/".to_owned()
                } else {
                    path
                },
                source: error.into_inner(),
            }
        })?;
        config.check()?;
        Ok(config)
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
            let path = error.path().to_string();
            RuntimeConfigError::PolicyParse {
                path: if path.is_empty() {
                    "/".to_owned()
                } else {
                    path
                },
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
        if self.api_version != SCHEDULING_RUNTIME_API_VERSION {
            return Err(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != SCHEDULING_RUNTIME_KIND {
            return Err(RuntimeConfigError::InvalidKind);
        }
        if !self.package.root.is_absolute() {
            return Err(RuntimeConfigError::RelativeOperatedPath("package.root"));
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
        if self.authentication.oidc.issuer.is_empty()
            || self.authentication.oidc.audience.is_empty()
            || self.authentication.oidc.scope_claim.is_empty()
            || self.authentication.oidc.reads_scope.is_empty()
            || self.authentication.oidc.explain_scope.is_empty()
            || self.authentication.oidc.explain_scope == self.authentication.oidc.reads_scope
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidDatabaseReference);
        }
        if self.audit.hash_key_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidAuditReference);
        }
        if self.retention.attempt_receipt_days == 0 {
            return Err(RuntimeConfigError::InvalidRetention);
        }
        if let Some(reminders) = &self.destinations.reminders {
            if !valid_destination_url(&reminders.url) {
                return Err(RuntimeConfigError::InvalidDestination);
            }
        }
        self.validate_secret_references()?;

        self.load_policy()?;
        if self.listener.tls_termination == TlsTermination::OperatorControlledUpstream
            && self.policy_package_digest()?.is_none()
        {
            return Err(RuntimeConfigError::ProductionPolicyPackageRequired);
        }
        #[cfg(not(feature = "postgres-test"))]
        if self.database.test_only_plaintext {
            return Err(RuntimeConfigError::PlaintextDatabase);
        }
        Ok(())
    }

    fn validate_secret_references(&self) -> Result<(), RuntimeConfigError> {
        let mut references = vec![
            (
                "database.runtimeUrlRef".to_owned(),
                &self.database.runtime_url_ref,
            ),
            (
                "database.migrationUrlRef".to_owned(),
                &self.database.migration_url_ref,
            ),
            ("audit.hashKeyRef".to_owned(), &self.audit.hash_key_ref),
        ];
        if let Some(reference) = &self.database.trusted_root_certificate_ref {
            references.push(("database.trustedRootCertificateRef".to_owned(), reference));
        }
        if let OidcJwksSource::Static { document_ref } = &self.authentication.oidc.jwks_source {
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
        for (path, raw) in references {
            let reference = SecretReference::parse(raw.clone())
                .map_err(|_| RuntimeConfigError::InvalidSecretReference { path: path.clone() })?;
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

    pub async fn oidc_verifier(
        &self,
        secrets: &SecretResolver,
    ) -> Result<(TokenVerifierConfig, std::sync::Arc<JwksFetcher>), RuntimeConfigError> {
        let discovery_config = OidcDiscoveryConfig {
            issuer: self.authentication.oidc.issuer.clone(),
            jwks_uri_override: self.authentication.oidc.jwks_uri.clone(),
            discovery_timeout: Duration::from_secs(5),
            max_doc_bytes: 1024 * 1024,
        };
        let fetcher = match &self.authentication.oidc.jwks_source {
            OidcJwksSource::Discovery => {
                let discovery = fetch_discovery(&discovery_config)
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
            self.authentication.oidc.issuer.clone(),
            vec![self.authentication.oidc.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set(SCHEDULING_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(self.authentication.oidc.allowed_clients.clone())
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

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
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

#[derive(Debug, Error)]
pub enum PolicyPackageError {
    #[error("the Scheduling policy package could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Scheduling policy package is invalid or does not match its exact inputs")]
    Invalid,
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error("the Scheduling runtime configuration could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Scheduling runtime configuration is not valid YAML at {path}")]
    Parse {
        path: String,
        #[source]
        source: serde_norway::Error,
    },
    #[error(
        "unsupported Scheduling runtime apiVersion; expected registry.registrystack.org/scheduling-runtime/v1alpha1"
    )]
    InvalidApiVersion,
    #[error("unsupported Scheduling runtime kind; expected SchedulingRuntimeConfig")]
    InvalidKind,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    #[error("the selected Scheduling runtime configuration path must be absolute")]
    RelativeRuntimePath,
    #[error("secretProviders must explicitly enable file, environment, or both")]
    InvalidSecretProviders,
    #[error("{path} is not a valid secret reference")]
    InvalidSecretReference { path: String },
    #[error("{path} uses a secret provider that is not explicitly enabled")]
    SecretProviderRequired { path: String },
    #[error("the authored scheduling policy could not be read")]
    PolicyRead(#[source] std::io::Error),
    #[error("the authored scheduling policy is not valid YAML at {path}")]
    PolicyParse { path: String },
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
    #[error("audit.hashKeyRef must be a non-empty secret reference")]
    InvalidAuditReference,
    #[error("retention.attemptReceiptDays must be at least one day")]
    InvalidRetention,
    #[error("destinations.reminders.url is not a valid destination URL")]
    InvalidDestination,
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
            Self::InvalidApiVersion => "apiVersion",
            Self::InvalidKind => "kind",
            Self::RelativeOperatedPath(path) => path,
            Self::RelativeRuntimePath | Self::Read(_) => "/",
            Self::Parse { path, .. } => path,
            Self::InvalidSecretProviders => "secretProviders",
            Self::InvalidSecretReference { path } | Self::SecretProviderRequired { path } => path,
            Self::InvalidOidc | Self::Oidc => "authentication.oidc",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener",
            Self::InvalidDatabaseReference | Self::PlaintextDatabase => "database",
            Self::InvalidAuditReference => "audit.hashKeyRef",
            Self::InvalidRetention => "retention.attemptReceiptDays",
            Self::InvalidDestination => "destinations.reminders.url",
            Self::PolicyRead(_) | Self::PolicyParse { .. } => "package.root/scheduling.yaml",
            Self::PolicyFindings | Self::PolicyPackage(_) => "package.root",
            Self::ProductionPolicyPackageRequired => "package.root",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_oidc::is_access_token_typ_pair;

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
windows: []
holdPolicy: {ttlMinutes: 10, maxPerCaller: 2, because: test}
"#;

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
                "audience": "urn:example:scheduling"
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
        let root = tempfile::tempdir().unwrap();
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
        assert!(config.destinations.reminders.is_none());
        let policy = config.load_policy().expect("policy loads");
        assert_eq!(policy.scheduling.id, "standalone-exact-time");
    }

    #[test]
    fn production_requires_a_verified_package_while_loopback_accepts_authoring() {
        let root = tempfile::tempdir().unwrap();
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
        let root = tempfile::tempdir().unwrap();
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
    fn a_policy_that_fails_its_checks_never_reaches_the_runtime() {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        write_policy(&package);
        // A hook is the one authored shape that always fails the check: this
        // milestone has no engine, so accepting it would be a silent no-op.
        let hooked = format!(
            "{POLICY}hooks:\n  - {{id: h, abi: registry.scheduling-hook/v1, because: test}}\n"
        );
        std::fs::write(package.join(AUTHORED_POLICY_FILE), hooked).unwrap();
        let operator = write_operator(
            root.path(),
            operator_value(&package, "development-loopback"),
        );
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::PolicyFindings)
        ));
    }

    #[test]
    fn typed_parse_path_does_not_echo_the_rejected_value() {
        let root = tempfile::tempdir().unwrap();
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
    fn the_access_token_profile_admits_only_the_rfc_9068_pair() {
        let root = tempfile::tempdir().unwrap();
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
        use std::net::{Ipv4Addr, Ipv6Addr};
        assert!(valid_listener(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(!valid_listener(
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(valid_listener(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(!valid_listener(
            "10.20.30.40".parse::<IpAddr>().unwrap(),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::DevelopmentLoopback,
        ));
    }

    #[test]
    fn static_jwks_requires_unique_named_asymmetric_keys() {
        assert!(parse_static_jwks(
            br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#
        )
        .is_ok());
        for invalid in [
            br#"{}"#.as_slice(),
            br#"{"keys":[]}"#,
            br#"{"keys":[{"kty":"oct","kid":"one","k":"AA"}]}"#,
            br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"},{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,
            b"not-json",
        ] {
            assert!(parse_static_jwks(invalid).is_err());
        }
    }
}
