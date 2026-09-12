use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::Algorithm;
use registry_casework_core::{check_routing_policy, CaseworkProject};
use registry_platform_config::{
    SecretError, SecretProvider, SecretReference, SecretResolver, MAX_SECRET_BYTES,
};
use registry_platform_oidc::{
    fetch_discovery, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, TokenVerifierConfig,
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

pub const POLICY_PACKAGE_API_VERSION: &str =
    "registry.registrystack.org/casework-policy-package/v1alpha1";
pub const POLICY_PACKAGE_KIND: &str = "CaseworkPolicyPackage";
pub const POLICY_PACKAGE_MANIFEST_FILE: &str = "casework.package.json";
pub const RUNTIME_CONFIG_API_VERSION: &str = "registry.registrystack.org/casework-runtime/v1alpha1";
pub const RUNTIME_CONFIG_KIND: &str = "CaseworkRuntimeConfig";
pub const POLICY_FILE: &str = "casework.yaml";
const MAXIMUM_POLICY_PACKAGE_FILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_POLICY_PACKAGE_MANIFEST_BYTES: usize = 1024 * 1024;

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
    /// Build the immutable identity for already validated policy inputs.
    pub fn build(
        files: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Result<Self, PolicyPackageError> {
        let mut files = files
            .into_iter()
            .map(|(path, bytes)| {
                if normalized_relative_path(&path).is_none()
                    || bytes.len() > MAXIMUM_POLICY_PACKAGE_FILE_BYTES
                {
                    return Err(PolicyPackageError::Invalid);
                }
                Ok(PolicyPackageFile {
                    path,
                    sha256: sha256_bytes(&bytes),
                    bytes: u64::try_from(bytes.len()).map_err(|_| PolicyPackageError::Invalid)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        files.sort_by(|left, right| left.path.cmp(&right.path));
        if !files.iter().any(|file| file.path == POLICY_FILE)
            || files.windows(2).any(|pair| pair[0].path == pair[1].path)
        {
            return Err(PolicyPackageError::Invalid);
        }
        let policy_digest =
            package_digest(POLICY_PACKAGE_API_VERSION, POLICY_PACKAGE_KIND, &files)?;
        Ok(Self {
            api_version: POLICY_PACKAGE_API_VERSION.to_owned(),
            kind: POLICY_PACKAGE_KIND.to_owned(),
            policy_digest,
            files,
        })
    }

    pub fn verify(&self, root: &Path, project: &CaseworkProject) -> Result<(), PolicyPackageError> {
        if self.api_version != POLICY_PACKAGE_API_VERSION
            || self.kind != POLICY_PACKAGE_KIND
            || self.files.is_empty()
            || self
                .files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
            || self.policy_digest != package_digest(&self.api_version, &self.kind, &self.files)?
        {
            return Err(PolicyPackageError::Invalid);
        }

        let mut expected = BTreeSet::from([POLICY_FILE.to_owned()]);
        for source in &project.sources {
            if normalized_relative_path(&source.description).is_none()
                || !expected.insert(source.description.clone())
            {
                return Err(PolicyPackageError::Invalid);
            }
        }
        let declared = self
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<BTreeSet<_>>();
        if declared != expected {
            return Err(PolicyPackageError::Invalid);
        }

        for file in &self.files {
            let relative =
                normalized_relative_path(&file.path).ok_or(PolicyPackageError::Invalid)?;
            let bytes = read_bounded_file(&root.join(relative), MAXIMUM_POLICY_PACKAGE_FILE_BYTES)?;
            if file.bytes != u64::try_from(bytes.len()).map_err(|_| PolicyPackageError::Invalid)?
                || file.sha256 != sha256_bytes(&bytes)
            {
                return Err(PolicyPackageError::Invalid);
            }
        }

        let mut on_disk = package_files_on_disk(root)?;
        on_disk.remove(POLICY_PACKAGE_MANIFEST_FILE);
        if on_disk != expected {
            return Err(PolicyPackageError::Invalid);
        }
        Ok(())
    }
}

/// Verify a package next to `casework.yaml`, returning its immutable identity.
/// An absent manifest is distinguished so local authored development remains usable.
pub fn verify_policy_package(
    project_path: &Path,
    project: &CaseworkProject,
) -> Result<Option<String>, PolicyPackageError> {
    if project_path.file_name().and_then(|name| name.to_str()) != Some(POLICY_FILE) {
        return Err(PolicyPackageError::Invalid);
    }
    let root = project_path.parent().ok_or(PolicyPackageError::Invalid)?;
    let manifest_path = root.join(POLICY_PACKAGE_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Ok(None);
    }
    let bytes = read_bounded_file(&manifest_path, MAXIMUM_POLICY_PACKAGE_MANIFEST_BYTES)?;
    let manifest: PolicyPackageManifest =
        serde_json::from_slice(&bytes).map_err(|_| PolicyPackageError::Invalid)?;
    manifest.verify(root, project)?;
    Ok(Some(manifest.policy_digest))
}

fn package_digest(
    api_version: &str,
    kind: &str,
    files: &[PolicyPackageFile],
) -> Result<String, PolicyPackageError> {
    let identity = serde_json::json!({
        "apiVersion": api_version,
        "kind": kind,
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

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, PolicyPackageError> {
    let metadata = std::fs::symlink_metadata(path).map_err(PolicyPackageError::Read)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum as u64
    {
        return Err(PolicyPackageError::Invalid);
    }
    std::fs::read(path).map_err(PolicyPackageError::Read)
}

fn package_files_on_disk(root: &Path) -> Result<BTreeSet<String>, PolicyPackageError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).map_err(PolicyPackageError::Read)? {
            let entry = entry.map_err(PolicyPackageError::Read)?;
            let metadata =
                std::fs::symlink_metadata(entry.path()).map_err(PolicyPackageError::Read)?;
            if metadata.file_type().is_symlink() {
                return Err(PolicyPackageError::Invalid);
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| PolicyPackageError::Invalid)?
                    .to_str()
                    .ok_or(PolicyPackageError::Invalid)?
                    .to_owned();
                if normalized_relative_path(&relative).is_none() || !files.insert(relative) {
                    return Err(PolicyPackageError::Invalid);
                }
            } else {
                return Err(PolicyPackageError::Invalid);
            }
        }
    }
    Ok(files)
}

#[derive(Debug, Error)]
pub enum PolicyPackageError {
    #[error("the Casework policy package could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Casework policy package is invalid or does not match its exact inputs")]
    Invalid,
}

/// Validate one imported BReg description through the adapter's owning strict
/// decoder without resolving runtime bindings or secrets.
pub fn validate_breg_source_description(
    source: &registry_casework_core::SourcePolicy,
    bytes: &[u8],
) -> Result<registry_casework_core::RoutingSourceMetadata, registry_casework_core::SourceAdapterError>
{
    registry_casework_breg::validate_description_input(source, bytes)
}

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
    pub task_authority: Option<TaskAuthorityConfig>,
    #[serde(default)]
    pub sources: BTreeMap<String, registry_casework_breg::BregBinding>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskAuthorityConfig {
    pub id: String,
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
    "127.0.0.1:8100"
        .parse()
        .expect("valid Casework listener default")
}

/// Declares the trusted transport boundary for the runtime's plaintext HTTP listener.
///
/// Production listeners require operator-controlled upstream TLS termination.
/// Direct plaintext is limited to the explicit loopback-only development mode.
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

fn default_scope_claim() -> String {
    "registry_scopes".to_owned()
}
fn default_human_identity_claim() -> String {
    "registry_actor_kind".to_owned()
}
fn default_human_identity_value() -> String {
    "human".to_owned()
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    pub hash_key_ref: String,
}

impl RuntimeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        if !path.as_ref().is_absolute() {
            return Err(RuntimeConfigError::RelativeRuntimePath);
        }
        let bytes = std::fs::read(path.as_ref()).map_err(RuntimeConfigError::Read)?;
        let value: serde_norway::Value =
            serde_norway::from_slice(&bytes).map_err(|source| RuntimeConfigError::Parse {
                path: "/".to_owned(),
                source,
            })?;
        if value
            .get("authentication")
            .and_then(|value| value.get("oidc"))
            .and_then(|value| value.get("principalClaim"))
            .is_some()
        {
            return Err(RuntimeConfigError::RemovedPrincipalClaim);
        }
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
        self.package.root.join(POLICY_FILE)
    }

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if self.api_version != RUNTIME_CONFIG_API_VERSION {
            return Err(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != RUNTIME_CONFIG_KIND {
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
        self.validate_secret_references()?;
        let policy_path = self.policy_path();
        let project = CaseworkProject::load(&policy_path).map_err(RuntimeConfigError::Project)?;
        let package_digest = verify_policy_package(&policy_path, &project)
            .map_err(RuntimeConfigError::PolicyPackage)?;
        if self.listener.tls_termination == TlsTermination::OperatorControlledUpstream
            && package_digest.is_none()
        {
            return Err(RuntimeConfigError::ProductionPolicyPackageRequired);
        }
        validate_project_source_inputs(&policy_path, &project)?;
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
            || self.authentication.oidc.human_identity.claim.is_empty()
            || self.authentication.oidc.human_identity.value.is_empty()
            || self.authentication.oidc.human_identity.claim == self.authentication.oidc.scope_claim
            || project.access_profiles.iter().any(|profile| {
                profile.principal_claim == self.authentication.oidc.human_identity.claim
            })
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        if let Some(authority) = &self.task_authority {
            if authority.id.is_empty()
                || authority.id.len() > 128
                || !registry_platform_httputil::valid_resource_uri(&authority.issuer)
                || !registry_platform_httputil::valid_resource_uri(&authority.exchange_audience)
                || self.authentication.oidc.allowed_clients.is_empty()
                || authority.status_clients.len() > 64
                || authority.status_clients.iter().any(|(client, resource)| {
                    !self.authentication.oidc.allowed_clients.contains(client)
                        || !registry_platform_httputil::valid_resource_uri(resource)
                })
                || project.task_templates.iter().any(|template| {
                    template.agent.issuer != self.authentication.oidc.issuer
                        || !self
                            .authentication
                            .oidc
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
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidDatabaseReference);
        }
        if self.audit.hash_key_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidAuditReference);
        }
        if self.sources.keys().any(String::is_empty) || configured_sources != declared_sources {
            return Err(RuntimeConfigError::InvalidSourceBindings);
        }
        #[cfg(not(feature = "postgres-test"))]
        if self.database.test_only_plaintext {
            return Err(RuntimeConfigError::PlaintextDatabase);
        }
        Ok(())
    }

    /// Return the verified deployment policy identity, if this is a packaged
    /// local-development configuration. Production configurations always have one.
    pub fn policy_package_digest(&self) -> Result<Option<String>, RuntimeConfigError> {
        let policy_path = self.policy_path();
        let project = CaseworkProject::load(&policy_path).map_err(RuntimeConfigError::Project)?;
        verify_policy_package(&policy_path, &project).map_err(RuntimeConfigError::PolicyPackage)
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
        let verifier = TokenVerifierConfig::access_token_profile(
            self.authentication.oidc.issuer.clone(),
            vec![self.authentication.oidc.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            vec!["at+jwt".to_owned(), "JWT".to_owned()],
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(self.authentication.oidc.allowed_clients.clone());
        Ok((verifier, std::sync::Arc::new(fetcher)))
    }
}

fn validate_project_source_inputs(
    project_path: &Path,
    project: &CaseworkProject,
) -> Result<(), RuntimeConfigError> {
    let root = project_path.parent().ok_or(RuntimeConfigError::Invalid)?;
    let queues = project
        .queues
        .iter()
        .map(|queue| queue.id.clone())
        .collect::<BTreeSet<_>>();
    for source in &project.sources {
        if source.adapter != "breg" || source.requests.len() != 1 {
            return Err(RuntimeConfigError::SourceDescription);
        }
        let relative = normalized_relative_path(&source.description)
            .ok_or(RuntimeConfigError::SourceDescription)?;
        let bytes = read_bounded_file(&root.join(relative), MAXIMUM_POLICY_PACKAGE_FILE_BYTES)
            .map_err(|_| RuntimeConfigError::SourceDescription)?;
        let metadata = validate_breg_source_description(source, &bytes)
            .map_err(|_| RuntimeConfigError::SourceDescription)?;
        for request in &source.requests {
            check_routing_policy(
                &request.queue,
                &request.projection,
                &request.routing,
                &queues,
                Some(&metadata),
            )
            .map_err(|_| RuntimeConfigError::SourceDescription)?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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
    "reviewMode":"staged",
    "stages":[{"id":"review","approvals":1,"excludeSubmitter":true,"excludePreviousReviewers":false}],
    "fields":[],
    "contractFingerprint":"sha256:contract",
    "application":{"mode":"manual"}
  }
}
"#;

    fn write_package(root: &Path) -> PolicyPackageManifest {
        std::fs::create_dir_all(root.join("sources")).unwrap();
        std::fs::write(root.join("casework.yaml"), SOURCE_PROJECT).unwrap();
        std::fs::write(root.join("sources/professional.json"), SOURCE_DESCRIPTION).unwrap();
        let manifest = PolicyPackageManifest::build([
            (
                "casework.yaml".to_owned(),
                SOURCE_PROJECT.as_bytes().to_vec(),
            ),
            (
                "sources/professional.json".to_owned(),
                SOURCE_DESCRIPTION.as_bytes().to_vec(),
            ),
        ])
        .unwrap();
        let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        bytes.push(b'\n');
        std::fs::write(root.join(POLICY_PACKAGE_MANIFEST_FILE), bytes).unwrap();
        manifest
    }

    fn operator_document(package: &Path, tls: &str) -> String {
        serde_norway::to_string(&operator_value(package, tls)).unwrap()
    }

    fn operator_value(package: &Path, tls: &str) -> serde_json::Value {
        let root = package.parent().expect("package parent");
        serde_json::json!({
            "apiVersion": RUNTIME_CONFIG_API_VERSION,
            "kind": RUNTIME_CONFIG_KIND,
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
        })
    }

    #[test]
    fn static_jwks_requires_unique_named_asymmetric_keys() {
        assert!(parse_static_jwks(
            br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#
        )
        .is_ok());
        for invalid in [br#"{}"#.as_slice(),br#"{"keys":[]}"#,br#"{"keys":[{"kty":"oct","kid":"one","k":"AA"}]}"#,br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"},{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,b"not-json"] {
            assert!(parse_static_jwks(invalid).is_err());
        }
    }

    /// The commented alternative in the operator example must be loadable
    /// exactly as written, and its refusal must name the reference an operator
    /// has to go and fix.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_static_jwks_source_loads_and_names_its_reference_when_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
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
            &config.authentication.oidc.jwks_source,
            OidcJwksSource::Static { document_ref } if document_ref == "secret:file/jwks.json"
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
        let OidcJwksSource::Static { document_ref } = &mut config.authentication.oidc.jwks_source
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

    #[test]
    fn static_source_uses_document_ref_camel_case() {
        let source: OidcJwksSource =
            serde_json::from_str(r#"{"kind":"static","documentRef":"secret:file/keys.json"}"#)
                .expect("static source");
        assert!(
            matches!(source,OidcJwksSource::Static{document_ref} if document_ref=="secret:file/keys.json")
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
    }

    #[test]
    fn package_identity_covers_exact_policy_and_imported_inputs() {
        let package = tempfile::tempdir().unwrap();
        let manifest = write_package(package.path());
        let project = CaseworkProject::load(package.path().join("casework.yaml")).unwrap();
        assert_eq!(
            verify_policy_package(&package.path().join("casework.yaml"), &project).unwrap(),
            Some(manifest.policy_digest)
        );

        std::fs::write(package.path().join("sources/stale.json"), b"stale").unwrap();
        assert!(verify_policy_package(&package.path().join("casework.yaml"), &project).is_err());
        std::fs::remove_file(package.path().join("sources/stale.json")).unwrap();
        std::fs::write(package.path().join("sources/professional.json"), b"changed").unwrap();
        assert!(verify_policy_package(&package.path().join("casework.yaml"), &project).is_err());
    }

    #[test]
    fn production_requires_a_verified_package_while_loopback_accepts_authoring() {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("operator.yaml");
        std::fs::write(
            &operator,
            operator_document(&package, "operator-controlled-upstream"),
        )
        .unwrap();
        let config = RuntimeConfig::load(&operator).unwrap();
        assert!(config.policy_package_digest().unwrap().is_some());

        std::fs::remove_file(package.join(POLICY_PACKAGE_MANIFEST_FILE)).unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::ProductionPolicyPackageRequired)
        ));
        std::fs::write(
            &operator,
            operator_document(&package, "development-loopback"),
        )
        .unwrap();
        assert!(RuntimeConfig::load(&operator).is_ok());
    }

    #[test]
    fn runtime_envelope_listener_and_operated_paths_are_strict() {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let operator = root.path().join("runtime.yaml");
        let valid = operator_document(&package, "operator-controlled-upstream");
        let defaulted_bind = valid.replace("  bind: 127.0.0.1:8100\n", "");
        std::fs::write(&operator, &defaulted_bind).unwrap();
        assert_eq!(
            RuntimeConfig::load(&operator).unwrap().listener.bind.port(),
            8100
        );

        assert!(matches!(
            RuntimeConfig::load("runtime.yaml"),
            Err(RuntimeConfigError::RelativeRuntimePath)
        ));

        std::fs::write(
            &operator,
            valid.replace(RUNTIME_CONFIG_API_VERSION, "registry.example/unsupported"),
        )
        .unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::InvalidApiVersion)
        ));

        std::fs::write(
            &operator,
            valid.replace("  tlsTermination: operator-controlled-upstream\n", ""),
        )
        .unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::Parse { .. })
        ));
    }

    #[test]
    fn removed_runtime_principal_claim_names_the_authored_replacement() {
        let root = tempfile::tempdir().unwrap();
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
        assert!(matches!(&error, RuntimeConfigError::RemovedPrincipalClaim));
        assert!(error
            .to_string()
            .contains("accessProfiles[].principalClaim"));
    }

    #[test]
    fn environment_secret_references_require_the_explicit_provider() {
        let root = tempfile::tempdir().unwrap();
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
            RuntimeConfigError::SecretProviderRequired { path }
                if path == "database.runtimeUrlRef"
        ));
        assert_eq!(error.path(), "database.runtimeUrlRef");
    }

    #[test]
    fn typed_parse_path_does_not_echo_the_rejected_value() {
        let root = tempfile::tempdir().unwrap();
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
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        write_package(&package);
        let invalid_description = b"{}\n";
        std::fs::write(
            package.join("sources/professional.json"),
            invalid_description,
        )
        .unwrap();
        let manifest = PolicyPackageManifest::build([
            (
                "casework.yaml".to_owned(),
                SOURCE_PROJECT.as_bytes().to_vec(),
            ),
            (
                "sources/professional.json".to_owned(),
                invalid_description.to_vec(),
            ),
        ])
        .unwrap();
        std::fs::write(
            package.join(POLICY_PACKAGE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
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
        use std::net::{Ipv4Addr, Ipv6Addr};

        assert!(valid_listener(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(valid_listener(
            "10.20.30.40".parse().expect("private IPv4"),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(!valid_listener(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(valid_listener(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(!valid_listener(
            "203.0.113.10".parse().expect("public IPv4"),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(valid_listener(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::DevelopmentLoopback,
        ));
        assert!(!valid_listener(
            "10.20.30.40".parse().expect("private IPv4"),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::DevelopmentLoopback,
        ));
        assert!(!valid_listener(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::DevelopmentLoopback,
        ));
    }
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error("the Casework runtime configuration could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Casework runtime configuration is not valid YAML at {path}")]
    Parse {
        path: String,
        #[source]
        source: serde_norway::Error,
    },
    #[error("unsupported Casework runtime apiVersion; expected registry.registrystack.org/casework-runtime/v1alpha1")]
    InvalidApiVersion,
    #[error("unsupported Casework runtime kind; expected CaseworkRuntimeConfig")]
    InvalidKind,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    #[error("the selected Casework runtime configuration path must be absolute")]
    RelativeRuntimePath,
    #[error("secretProviders must explicitly enable file, environment, or both")]
    InvalidSecretProviders,
    #[error("{path} is not a valid secret reference")]
    InvalidSecretReference { path: String },
    #[error("{path} uses a secret provider that is not explicitly enabled")]
    SecretProviderRequired { path: String },
    #[error("authentication.oidc.principalClaim has been removed; configure accessProfiles[].principalClaim in casework.yaml")]
    RemovedPrincipalClaim,
    #[error("the Casework project is invalid")]
    Project(#[source] registry_casework_core::ConfigLoadError),
    #[error("the Casework policy package is invalid")]
    PolicyPackage(#[source] PolicyPackageError),
    #[error("operator-controlled production requires a verified Casework policy package")]
    ProductionPolicyPackageRequired,
    #[error("an imported source description does not match the exact configured source policy")]
    SourceDescription,
    #[error("the Casework runtime configuration is invalid")]
    Invalid,
    #[error("listener is not valid for its declared TLS termination and network exposure")]
    InvalidListener,
    #[error("authentication.oidc is invalid or conflicts with accessProfiles[].principalClaim")]
    InvalidOidc,
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error("audit.hashKeyRef must be a non-empty secret reference")]
    InvalidAuditReference,
    #[error("sources must exactly match the source ids declared by package.root/casework.yaml")]
    InvalidSourceBindings,
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
            Self::RemovedPrincipalClaim => "authentication.oidc.principalClaim",
            Self::InvalidOidc | Self::Oidc => "authentication.oidc",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener",
            Self::InvalidDatabaseReference | Self::PlaintextDatabase => "database",
            Self::InvalidAuditReference => "audit.hashKeyRef",
            Self::InvalidSourceBindings | Self::SourceDescription => "sources",
            Self::Project(_) => "package.root/casework.yaml",
            Self::PolicyPackage(_) | Self::ProductionPolicyPackageRequired => "package.root",
            Self::Invalid => "/",
        }
    }
}
