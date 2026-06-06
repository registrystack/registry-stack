//! Governed runtime configuration verification contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::UnparsedPublicKey;
use bytes::Bytes;
use futures_core::Stream;
use olpc_cjson::CanonicalFormatter;
use registry_platform_httputil::{read_bounded, FetchUrlPolicy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tough::schema::key::{EcdsaScheme, Ed25519Scheme, Key, RsaScheme};
use tough::schema::{RoleType, Root, Signed, Targets};
use tough::{
    ExpirationEnforcement, FilesystemTransport, IntoVec, RepositoryLoader, TargetName, Transport,
    TransportError, TransportErrorKind, TransportStream,
};
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerificationContext {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocalTufRepositoryInput {
    pub root_path: PathBuf,
    pub metadata_dir: PathBuf,
    pub targets_dir: PathBuf,
    pub datastore_dir: PathBuf,
    pub target_name: String,
}

impl LocalTufRepositoryInput {
    pub fn validate(&self) -> Result<(), ConfigVerificationError> {
        validate_non_empty_path("root_path", &self.root_path)?;
        validate_non_empty_path("metadata_dir", &self.metadata_dir)?;
        validate_non_empty_path("targets_dir", &self.targets_dir)?;
        validate_non_empty_path("datastore_dir", &self.datastore_dir)?;
        validate_non_empty("target_name", &self.target_name)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RemoteTufRepositoryInput {
    pub root_path: PathBuf,
    pub metadata_base_url: String,
    pub targets_base_url: String,
    pub datastore_dir: PathBuf,
    pub target_name: String,
    pub allow_dev_insecure_fetch_urls: bool,
}

impl RemoteTufRepositoryInput {
    pub fn validate(&self) -> Result<(Url, Url), ConfigVerificationError> {
        validate_non_empty_path("root_path", &self.root_path)?;
        validate_non_empty("metadata_base_url", &self.metadata_base_url)?;
        validate_non_empty("targets_base_url", &self.targets_base_url)?;
        validate_non_empty_path("datastore_dir", &self.datastore_dir)?;
        validate_non_empty("target_name", &self.target_name)?;
        let metadata_base_url =
            parse_remote_base_url("metadata_base_url", &self.metadata_base_url)?;
        let targets_base_url = parse_remote_base_url("targets_base_url", &self.targets_base_url)?;
        Ok((metadata_base_url, targets_base_url))
    }

    fn fetch_policy(&self) -> FetchUrlPolicy {
        if self.allow_dev_insecure_fetch_urls {
            FetchUrlPolicy::dev()
        } else {
            FetchUrlPolicy::strict()
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TufVerifiedTarget {
    pub target_name: String,
    pub target_bytes: Vec<u8>,
    pub custom_metadata: Value,
    pub root_sha256: String,
    pub signer_kids: Vec<String>,
    pub root_version: u64,
    pub targets_version: u64,
    pub snapshot_version: u64,
    pub timestamp_version: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedConfigTarget {
    pub tuf: TufVerifiedTarget,
    pub metadata: ConfigTargetMetadata,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TufConfigVerifier;

impl TufConfigVerifier {
    pub async fn verify_local_target(
        input: &LocalTufRepositoryInput,
    ) -> Result<TufVerifiedTarget, ConfigVerificationError> {
        input.validate()?;
        let root = tokio::fs::read(&input.root_path)
            .await
            .map_err(|error| ConfigVerificationError::Io(error.to_string()))?;
        let metadata_url = dir_url(&input.metadata_dir)?;
        let targets_url = dir_url(&input.targets_dir)?;
        let repository = RepositoryLoader::new(&root, metadata_url, targets_url)
            .transport(FilesystemTransport)
            .expiration_enforcement(ExpirationEnforcement::Safe)
            .datastore(&input.datastore_dir)
            .load()
            .await
            .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?;
        let target_name = TargetName::new(&input.target_name)
            .map_err(|error| ConfigVerificationError::InvalidTargetName(error.to_string()))?;
        let mut stream = repository
            .read_target(&target_name)
            .await
            .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?
            .ok_or_else(|| ConfigVerificationError::TargetNotFound(input.target_name.clone()))?;
        let target_bytes = IntoVec::into_vec(&mut stream)
            .await
            .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?;
        let custom_metadata = repository
            .targets()
            .signed
            .targets
            .get(&target_name)
            .map(|target| {
                Value::Object(
                    target
                        .custom
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                )
            })
            .ok_or_else(|| ConfigVerificationError::TargetNotFound(input.target_name.clone()))?;
        let root_version = repository.root().signed.version.into();
        let root_sha256 =
            verified_local_root_sha256(&input.metadata_dir, &root, root_version).await?;
        let signer_kids =
            verified_targets_signer_kids(&repository.root().signed, repository.targets())?;
        Ok(TufVerifiedTarget {
            target_name: input.target_name.clone(),
            target_bytes,
            custom_metadata,
            root_sha256,
            signer_kids,
            root_version,
            targets_version: repository.targets().signed.version.into(),
            snapshot_version: repository.snapshot().signed.version.into(),
            timestamp_version: repository.timestamp().signed.version.into(),
        })
    }

    pub async fn verify_remote_target(
        input: &RemoteTufRepositoryInput,
    ) -> Result<TufVerifiedTarget, ConfigVerificationError> {
        let (metadata_url, targets_url) = input.validate()?;
        let root = tokio::fs::read(&input.root_path)
            .await
            .map_err(|error| ConfigVerificationError::Io(error.to_string()))?;
        let transport = GuardedRemoteTransport::new(input.fetch_policy());
        transport.validate_base_url(&metadata_url)?;
        transport.validate_base_url(&targets_url)?;
        let metadata_base_url = metadata_url.clone();
        let repository = RepositoryLoader::new(&root, metadata_url, targets_url)
            .transport(transport.clone())
            .expiration_enforcement(ExpirationEnforcement::Safe)
            .datastore(&input.datastore_dir)
            .load()
            .await
            .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?;
        let target_name = TargetName::new(&input.target_name)
            .map_err(|error| ConfigVerificationError::InvalidTargetName(error.to_string()))?;
        let mut stream = repository
            .read_target(&target_name)
            .await
            .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?
            .ok_or_else(|| ConfigVerificationError::TargetNotFound(input.target_name.clone()))?;
        let target_bytes = IntoVec::into_vec(&mut stream)
            .await
            .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?;
        let custom_metadata = repository
            .targets()
            .signed
            .targets
            .get(&target_name)
            .map(|target| {
                Value::Object(
                    target
                        .custom
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                )
            })
            .ok_or_else(|| ConfigVerificationError::TargetNotFound(input.target_name.clone()))?;
        let root_version = repository.root().signed.version.into();
        let root_sha256 =
            verified_remote_root_sha256(metadata_base_url, &transport, &root, root_version).await?;
        let signer_kids =
            verified_targets_signer_kids(&repository.root().signed, repository.targets())?;
        Ok(TufVerifiedTarget {
            target_name: input.target_name.clone(),
            target_bytes,
            custom_metadata,
            root_sha256,
            signer_kids,
            root_version,
            targets_version: repository.targets().signed.version.into(),
            snapshot_version: repository.snapshot().signed.version.into(),
            timestamp_version: repository.timestamp().signed.version.into(),
        })
    }

    pub async fn verify_config_target(
        input: &LocalTufRepositoryInput,
        context: &VerificationContext,
    ) -> Result<VerifiedConfigTarget, ConfigVerificationError> {
        let tuf = Self::verify_local_target(input).await?;
        let mut metadata = ConfigTargetMetadata::from_custom_metadata(
            &tuf.custom_metadata,
            &tuf.target_bytes,
            context,
        )?;
        metadata.signer_kids = tuf.signer_kids.iter().cloned().collect();
        Ok(VerifiedConfigTarget { tuf, metadata })
    }

    pub async fn verify_remote_config_target(
        input: &RemoteTufRepositoryInput,
        context: &VerificationContext,
    ) -> Result<VerifiedConfigTarget, ConfigVerificationError> {
        let tuf = Self::verify_remote_target(input).await?;
        let mut metadata = ConfigTargetMetadata::from_custom_metadata(
            &tuf.custom_metadata,
            &tuf.target_bytes,
            context,
        )?;
        metadata.signer_kids = tuf.signer_kids.iter().cloned().collect();
        Ok(VerifiedConfigTarget { tuf, metadata })
    }
}

#[derive(Clone, Debug)]
struct GuardedRemoteTransport {
    policy: FetchUrlPolicy,
}

impl GuardedRemoteTransport {
    fn new(policy: FetchUrlPolicy) -> Self {
        Self { policy }
    }

    fn validate_base_url(&self, url: &Url) -> Result<(), ConfigVerificationError> {
        self.policy
            .validate_for_immediate_fetch(url)
            .map(|_| ())
            .map_err(|error| ConfigVerificationError::UnsafeRemoteUrl(error.to_string()))
    }

    async fn fetch_bytes(&self, url: Url) -> Result<Bytes, TransportError> {
        let validated = self
            .policy
            .validate_for_immediate_fetch_with_timeout(
                &url,
                registry_platform_httputil::DEFAULT_VALIDATED_FETCH_CONNECT_TIMEOUT,
            )
            .await
            .map_err(|error| {
                TransportError::new_with_cause(
                    TransportErrorKind::UnsupportedUrlScheme,
                    url.as_str(),
                    error.to_string(),
                )
            })?;
        let response = validated
            .immediate_get()
            .map_err(|error| {
                TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    url.as_str(),
                    error.to_string(),
                )
            })?
            .send()
            .await
            .map_err(|error| {
                TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), error)
            })?;
        if matches!(response.status().as_u16(), 403 | 404 | 410) {
            return Err(TransportError::new(
                TransportErrorKind::FileNotFound,
                url.as_str(),
            ));
        }
        let response = response.error_for_status().map_err(|error| {
            TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), error)
        })?;
        let body = read_bounded(response, 16 * 1024 * 1024)
            .await
            .map_err(|error| {
                TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), error)
            })?;
        Ok(Bytes::from(body))
    }
}

#[async_trait::async_trait]
impl Transport for GuardedRemoteTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let bytes = self.fetch_bytes(url).await?;
        Ok(Box::pin(SingleBytesStream { item: Some(bytes) }))
    }
}

struct SingleBytesStream {
    item: Option<Bytes>,
}

impl Stream for SingleBytesStream {
    type Item = Result<Bytes, TransportError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.item.take().map(Ok))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigTargetMetadata {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub bundle_id: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_config_hash: Option<String>,
    pub config_hash: String,
    #[serde(default)]
    pub change_classes: BTreeSet<String>,
    #[serde(default)]
    pub signer_kids: BTreeSet<String>,
    pub apply_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_target_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_index_target_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_manifest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_schema_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_schema_version: Option<String>,
}

impl ConfigTargetMetadata {
    pub fn from_custom_metadata(
        custom: &Value,
        target_bytes: &[u8],
        context: &VerificationContext,
    ) -> Result<Self, ConfigVerificationError> {
        let metadata: Self = serde_json::from_value(custom.clone())
            .map_err(|error| ConfigVerificationError::InvalidTargetMetadata(error.to_string()))?;
        metadata.validate(target_bytes, context)?;
        Ok(metadata)
    }

    pub fn validate(
        &self,
        target_bytes: &[u8],
        context: &VerificationContext,
    ) -> Result<(), ConfigVerificationError> {
        validate_non_empty("product", &self.product)?;
        validate_non_empty("instance_id", &self.instance_id)?;
        validate_non_empty("environment", &self.environment)?;
        validate_non_empty("stream_id", &self.stream_id)?;
        validate_non_empty("bundle_id", &self.bundle_id)?;
        validate_non_empty("config_hash", &self.config_hash)?;
        validate_non_empty("apply_policy", &self.apply_policy)?;
        if self.change_classes.is_empty() {
            return Err(ConfigVerificationError::MissingChangeClasses);
        }
        if self.signer_kids.is_empty() {
            return Err(ConfigVerificationError::MissingSigners);
        }
        if self.product != context.product {
            return Err(ConfigVerificationError::ContextMismatch("product"));
        }
        if self.instance_id != context.instance_id {
            return Err(ConfigVerificationError::ContextMismatch("instance_id"));
        }
        if self.environment != context.environment {
            return Err(ConfigVerificationError::ContextMismatch("environment"));
        }
        let actual = sha256_uri(target_bytes);
        if self.config_hash != actual {
            return Err(ConfigVerificationError::TargetHashMismatch {
                expected: self.config_hash.clone(),
                actual,
            });
        }
        if let Some(target_name) = self.metadata_target_name.as_deref() {
            validate_target_name(target_name)?;
        }
        if let Some(target_name) = self.package_index_target_name.as_deref() {
            validate_target_name(target_name)?;
        }
        validate_optional_sha256_uri(
            "source_manifest_digest",
            self.source_manifest_digest.as_deref(),
        )?;
        validate_optional_sha256_uri("package_digest", self.package_digest.as_deref())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRootSigner {
    pub kid: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRootRole {
    pub name: String,
    pub threshold: usize,
    pub signer_kids: Vec<String>,
    pub allowed_change_classes: BTreeSet<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryTrustRoot {
    pub root_id: String,
    pub production: bool,
    pub tuf_root_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_unix_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_unix_seconds: Option<u64>,
    #[serde(default)]
    pub high_risk_change_classes: BTreeSet<String>,
    pub signers: BTreeMap<String, TrustRootSigner>,
    pub roles: Vec<TrustRootRole>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryAcceptedTrustRoots {
    pub accepted_roots: Vec<RegistryTrustRoot>,
}

impl RegistryTrustRoot {
    pub fn validate(&self) -> Result<(), ConfigVerificationError> {
        validate_non_empty("root_id", &self.root_id)?;
        validate_sha256_uri("tuf_root_sha256", &self.tuf_root_sha256)?;
        if let (Some(valid_from), Some(valid_until)) =
            (self.valid_from_unix_seconds, self.valid_until_unix_seconds)
        {
            if valid_until <= valid_from {
                return Err(ConfigVerificationError::InvalidTrustRootValidityWindow {
                    root_id: self.root_id.clone(),
                    valid_from_unix_seconds: valid_from,
                    valid_until_unix_seconds: valid_until,
                });
            }
        }
        if self.roles.is_empty() {
            return Err(ConfigVerificationError::MissingRoles);
        }
        for role in &self.roles {
            validate_non_empty("role.name", &role.name)?;
            if role.threshold == 0 {
                return Err(ConfigVerificationError::InvalidThreshold {
                    role: role.name.clone(),
                });
            }
            if role.allowed_change_classes.is_empty() {
                return Err(ConfigVerificationError::MissingRoleChangeClasses {
                    role: role.name.clone(),
                });
            }
            let mut distinct_enabled = BTreeSet::new();
            let mut seen = BTreeSet::new();
            for kid in &role.signer_kids {
                validate_non_empty("role.signer_kids", kid)?;
                if !seen.insert(kid.clone()) {
                    return Err(ConfigVerificationError::DuplicateSignerKid {
                        role: role.name.clone(),
                        kid: kid.clone(),
                    });
                }
                match self.signers.get(kid) {
                    Some(signer) if signer.enabled => {
                        distinct_enabled.insert(kid.clone());
                    }
                    Some(_) => {
                        return Err(ConfigVerificationError::DisabledRoleSigner {
                            role: role.name.clone(),
                            kid: kid.clone(),
                        });
                    }
                    None => {
                        return Err(ConfigVerificationError::UnknownRoleSigner {
                            role: role.name.clone(),
                            kid: kid.clone(),
                        });
                    }
                }
            }
            if role.threshold > distinct_enabled.len() {
                return Err(ConfigVerificationError::ThresholdExceedsEnabledSigners {
                    role: role.name.clone(),
                    threshold: role.threshold,
                    enabled: distinct_enabled.len(),
                });
            }
            if self.production
                && role.threshold < 2
                && role
                    .allowed_change_classes
                    .iter()
                    .any(|class| self.high_risk_change_classes.contains(class))
            {
                return Err(
                    ConfigVerificationError::SingleSignerHighRiskProductionRole {
                        role: role.name.clone(),
                    },
                );
            }
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        change_classes: &BTreeSet<String>,
        signer_kids: &[String],
        tuf_root_sha256: &str,
    ) -> Result<(), ConfigVerificationError> {
        self.authorize_at(
            change_classes,
            signer_kids,
            tuf_root_sha256,
            current_unix_seconds()?,
        )
    }

    pub fn authorize_at(
        &self,
        change_classes: &BTreeSet<String>,
        signer_kids: &[String],
        tuf_root_sha256: &str,
        now_unix_seconds: u64,
    ) -> Result<(), ConfigVerificationError> {
        self.validate()?;
        self.authorize_validated_at(
            change_classes,
            signer_kids,
            tuf_root_sha256,
            now_unix_seconds,
        )
    }

    fn authorize_validated_at(
        &self,
        change_classes: &BTreeSet<String>,
        signer_kids: &[String],
        tuf_root_sha256: &str,
        now_unix_seconds: u64,
    ) -> Result<(), ConfigVerificationError> {
        if let Some(valid_from_unix_seconds) = self.valid_from_unix_seconds {
            if now_unix_seconds < valid_from_unix_seconds {
                return Err(ConfigVerificationError::TrustRootNotYetValid {
                    root_id: self.root_id.clone(),
                    valid_from_unix_seconds,
                    now_unix_seconds,
                });
            }
        }
        if let Some(valid_until_unix_seconds) = self.valid_until_unix_seconds {
            if now_unix_seconds >= valid_until_unix_seconds {
                return Err(ConfigVerificationError::TrustRootExpired {
                    root_id: self.root_id.clone(),
                    valid_until_unix_seconds,
                    now_unix_seconds,
                });
            }
        }
        if self.tuf_root_sha256 != tuf_root_sha256 {
            return Err(ConfigVerificationError::UntrustedTufRoot {
                expected: self.tuf_root_sha256.clone(),
                actual: tuf_root_sha256.to_string(),
            });
        }
        if change_classes.is_empty() {
            return Err(ConfigVerificationError::MissingChangeClasses);
        }
        for kid in signer_kids {
            if let Some(signer) = self.signers.get(kid) {
                if !signer.enabled {
                    return Err(ConfigVerificationError::DisabledSigner { kid: kid.clone() });
                }
            }
        }
        let distinct_signers: BTreeSet<&str> = signer_kids.iter().map(String::as_str).collect();
        for change_class in change_classes {
            let authorized = self.roles.iter().any(|role| {
                role.allowed_change_classes.contains(change_class)
                    && role
                        .signer_kids
                        .iter()
                        .filter(|kid| distinct_signers.contains(kid.as_str()))
                        .count()
                        >= role.threshold
            });
            if !authorized {
                return Err(ConfigVerificationError::UnauthorizedChangeClass {
                    change_class: change_class.clone(),
                });
            }
        }
        Ok(())
    }
}

impl RegistryAcceptedTrustRoots {
    pub fn validate(&self) -> Result<(), ConfigVerificationError> {
        if self.accepted_roots.is_empty() {
            return Err(ConfigVerificationError::MissingAcceptedTrustRoots);
        }
        for root in &self.accepted_roots {
            root.validate()?;
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        change_classes: &BTreeSet<String>,
        signer_kids: &[String],
        tuf_root_sha256: &str,
    ) -> Result<&RegistryTrustRoot, ConfigVerificationError> {
        self.authorize_at(
            change_classes,
            signer_kids,
            tuf_root_sha256,
            current_unix_seconds()?,
        )
    }

    pub fn authorize_at(
        &self,
        change_classes: &BTreeSet<String>,
        signer_kids: &[String],
        tuf_root_sha256: &str,
        now_unix_seconds: u64,
    ) -> Result<&RegistryTrustRoot, ConfigVerificationError> {
        if self.accepted_roots.is_empty() {
            return Err(ConfigVerificationError::MissingAcceptedTrustRoots);
        }
        let mut authorized = None;
        for root in &self.accepted_roots {
            root.validate()?;
            let root_authorized = root
                .authorize_validated_at(
                    change_classes,
                    signer_kids,
                    tuf_root_sha256,
                    now_unix_seconds,
                )
                .is_ok();
            if authorized.is_none() && root_authorized {
                authorized = Some(root);
            }
        }
        authorized.ok_or(ConfigVerificationError::NoAcceptedTrustRootAuthorized {
            root_count: self.accepted_roots.len(),
        })
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ConfigVerificationError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("{0} must not be empty")]
    EmptyPath(&'static str),
    #[error("target metadata is invalid: {0}")]
    InvalidTargetMetadata(String),
    #[error("target name is invalid: {0}")]
    InvalidTargetName(String),
    #[error("target '{0}' was not found in verified TUF repository")]
    TargetNotFound(String),
    #[error("local repository path could not be converted to a file URL")]
    InvalidRepositoryUrl,
    #[error("remote repository URL is not allowed: {0}")]
    UnsafeRemoteUrl(String),
    #[error("TUF verification failed: {0}")]
    Tuf(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("system clock error: {0}")]
    Clock(String),
    #[error("target metadata {0} does not match local runtime context")]
    ContextMismatch(&'static str),
    #[error("target payload hash mismatch: expected {expected}, actual {actual}")]
    TargetHashMismatch { expected: String, actual: String },
    #[error("target metadata must list at least one change class")]
    MissingChangeClasses,
    #[error("target metadata must list at least one signer kid")]
    MissingSigners,
    #[error("accepted trust roots must list at least one root")]
    MissingAcceptedTrustRoots,
    #[error("trust root must define at least one role")]
    MissingRoles,
    #[error("role '{role}' threshold must be at least 1")]
    InvalidThreshold { role: String },
    #[error("role '{role}' must allow at least one change class")]
    MissingRoleChangeClasses { role: String },
    #[error("role '{role}' lists duplicate signer kid '{kid}'")]
    DuplicateSignerKid { role: String, kid: String },
    #[error("role '{role}' references unknown signer kid '{kid}'")]
    UnknownRoleSigner { role: String, kid: String },
    #[error("role '{role}' references disabled signer kid '{kid}'")]
    DisabledRoleSigner { role: String, kid: String },
    #[error("role '{role}' threshold {threshold} exceeds {enabled} enabled signer(s)")]
    ThresholdExceedsEnabledSigners {
        role: String,
        threshold: usize,
        enabled: usize,
    },
    #[error("role '{role}' authorizes high-risk production changes with one signer")]
    SingleSignerHighRiskProductionRole { role: String },
    #[error(
        "trust root '{root_id}' validity window is invalid: from {valid_from_unix_seconds}, until {valid_until_unix_seconds}"
    )]
    InvalidTrustRootValidityWindow {
        root_id: String,
        valid_from_unix_seconds: u64,
        valid_until_unix_seconds: u64,
    },
    #[error("{field} must be a sha256: URI")]
    InvalidSha256Uri { field: &'static str },
    #[error("trust root '{root_id}' is not valid until {valid_from_unix_seconds}")]
    TrustRootNotYetValid {
        root_id: String,
        valid_from_unix_seconds: u64,
        now_unix_seconds: u64,
    },
    #[error("trust root '{root_id}' expired at {valid_until_unix_seconds}")]
    TrustRootExpired {
        root_id: String,
        valid_until_unix_seconds: u64,
        now_unix_seconds: u64,
    },
    #[error("verified TUF root hash is not trusted")]
    UntrustedTufRoot { expected: String, actual: String },
    #[error("unknown signer kid '{kid}'")]
    UnknownSigner { kid: String },
    #[error("disabled signer kid '{kid}'")]
    DisabledSigner { kid: String },
    #[error("no role authorized change class '{change_class}' for the supplied signers")]
    UnauthorizedChangeClass { change_class: String },
    #[error("no accepted trust root authorized the verified target")]
    NoAcceptedTrustRootAuthorized { root_count: usize },
}

pub fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), ConfigVerificationError> {
    if value.trim().is_empty() {
        return Err(ConfigVerificationError::EmptyField(field));
    }
    Ok(())
}

fn validate_non_empty_path(
    field: &'static str,
    value: &Path,
) -> Result<(), ConfigVerificationError> {
    if value.as_os_str().is_empty() {
        return Err(ConfigVerificationError::EmptyPath(field));
    }
    Ok(())
}

fn validate_sha256_uri(field: &'static str, value: &str) -> Result<(), ConfigVerificationError> {
    validate_non_empty(field, value)?;
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(ConfigVerificationError::InvalidSha256Uri { field });
    };
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ConfigVerificationError::InvalidSha256Uri { field });
    }
    Ok(())
}

fn validate_optional_sha256_uri(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ConfigVerificationError> {
    if let Some(value) = value {
        validate_sha256_uri(field, value)?;
    }
    Ok(())
}

fn validate_target_name(value: &str) -> Result<(), ConfigVerificationError> {
    TargetName::new(value)
        .map_err(|error| ConfigVerificationError::InvalidTargetName(error.to_string()))?;
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
    {
        return Err(ConfigVerificationError::InvalidTargetName(
            "metadata target name must be relative and must not contain parent traversal"
                .to_string(),
        ));
    }
    Ok(())
}

fn dir_url(path: &Path) -> Result<Url, ConfigVerificationError> {
    Url::from_directory_path(path).map_err(|()| ConfigVerificationError::InvalidRepositoryUrl)
}

fn parse_remote_base_url(field: &'static str, value: &str) -> Result<Url, ConfigVerificationError> {
    let url = Url::parse(value)
        .map_err(|error| ConfigVerificationError::UnsafeRemoteUrl(error.to_string()))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(ConfigVerificationError::UnsafeRemoteUrl(format!(
            "{field} must use http or https"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigVerificationError::UnsafeRemoteUrl(format!(
            "{field} must not include userinfo"
        )));
    }
    Ok(url)
}

fn current_unix_seconds() -> Result<u64, ConfigVerificationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| ConfigVerificationError::Clock(error.to_string()))
}

fn verified_targets_signer_kids(
    root: &Root,
    targets: &Signed<Targets>,
) -> Result<Vec<String>, ConfigVerificationError> {
    let role_keys = root
        .roles
        .get(&RoleType::Targets)
        .ok_or_else(|| ConfigVerificationError::Tuf("missing targets role".to_string()))?;
    let signed_bytes = canonical_role_bytes(&targets.signed, "targets")?;
    let mut seen = BTreeSet::new();
    let mut signer_kids = Vec::new();

    for signature in &targets.signatures {
        if !role_keys.keyids.contains(&signature.keyid) {
            continue;
        }
        let Some(key) = root.keys.get(&signature.keyid) else {
            continue;
        };
        if verify_tuf_signature(key, &signed_bytes, signature.sig.as_ref()) {
            let kid = hex_lower(&signature.keyid);
            if seen.insert(kid.clone()) {
                signer_kids.push(kid);
            }
        }
    }

    if signer_kids.len() as u64 >= role_keys.threshold.get() {
        Ok(signer_kids)
    } else {
        Err(ConfigVerificationError::Tuf(format!(
            "targets role verified but only {} verified signer kid(s) were recoverable for threshold {}",
            signer_kids.len(),
            role_keys.threshold
        )))
    }
}

fn canonical_role_bytes<T: Serialize>(
    role: &T,
    what: &'static str,
) -> Result<Vec<u8>, ConfigVerificationError> {
    let mut data = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
    role.serialize(&mut serializer).map_err(|error| {
        ConfigVerificationError::Tuf(format!("{what} role canonicalization failed: {error}"))
    })?;
    Ok(data)
}

fn verify_tuf_signature(key: &Key, message: &[u8], signature: &[u8]) -> bool {
    let (algorithm, public_key): (&dyn aws_lc_rs::signature::VerificationAlgorithm, &[u8]) =
        match key {
            Key::Ecdsa {
                scheme: EcdsaScheme::EcdsaSha2Nistp256,
                keyval,
                ..
            }
            | Key::EcdsaOld {
                scheme: EcdsaScheme::EcdsaSha2Nistp256,
                keyval,
                ..
            } => (
                &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
                keyval.public.as_ref(),
            ),
            Key::Ed25519 {
                scheme: Ed25519Scheme::Ed25519,
                keyval,
                ..
            } => (&aws_lc_rs::signature::ED25519, keyval.public.as_ref()),
            Key::Rsa {
                scheme: RsaScheme::RsassaPssSha256,
                keyval,
                ..
            } => (
                &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA256,
                keyval.public.as_ref(),
            ),
        };

    UnparsedPublicKey::new(algorithm, public_key)
        .verify(message, signature)
        .is_ok()
}

async fn verified_local_root_sha256(
    metadata_dir: &Path,
    bootstrap_root: &[u8],
    root_version: u64,
) -> Result<String, ConfigVerificationError> {
    let bootstrap_version = bootstrap_root_version(bootstrap_root)?;
    if root_version == bootstrap_version {
        return Ok(sha256_uri(bootstrap_root));
    }
    let versioned_root_path = metadata_dir.join(format!("{root_version}.root.json"));
    let final_root = tokio::fs::read(&versioned_root_path)
        .await
        .map_err(|error| ConfigVerificationError::Io(error.to_string()))?;
    Ok(sha256_uri(&final_root))
}

async fn verified_remote_root_sha256(
    metadata_base_url: Url,
    transport: &GuardedRemoteTransport,
    bootstrap_root: &[u8],
    root_version: u64,
) -> Result<String, ConfigVerificationError> {
    let bootstrap_version = bootstrap_root_version(bootstrap_root)?;
    if root_version == bootstrap_version {
        return Ok(sha256_uri(bootstrap_root));
    }
    let versioned_root_url = append_url_path_segment(
        metadata_base_url,
        &format!("{root_version}.root.json"),
        "metadata_base_url",
    )?;
    let final_root = transport
        .fetch_bytes(versioned_root_url)
        .await
        .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?;
    Ok(sha256_uri(&final_root))
}

fn bootstrap_root_version(bootstrap_root: &[u8]) -> Result<u64, ConfigVerificationError> {
    let root: Signed<Root> = serde_json::from_slice(bootstrap_root)
        .map_err(|error| ConfigVerificationError::Tuf(error.to_string()))?;
    Ok(root.signed.version.into())
}

fn append_url_path_segment(
    mut base: Url,
    segment: &str,
    field: &'static str,
) -> Result<Url, ConfigVerificationError> {
    base.path_segments_mut()
        .map_err(|_| {
            ConfigVerificationError::UnsafeRemoteUrl(format!(
                "{field} cannot be used as a base URL"
            ))
        })?
        .pop_if_empty()
        .push(segment);
    Ok(base)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tough_fixture_dir(name: &str) -> PathBuf {
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
            .expect("CARGO_HOME or HOME is set");
        let src_root = cargo_home.join("registry/src");
        let registry = std::fs::read_dir(&src_root)
            .expect("cargo registry src exists")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("tough-0.22.0/tests/data").is_dir())
            .expect("tough-0.22.0 source fixture directory exists");
        registry.join("tough-0.22.0/tests/data").join(name)
    }

    #[tokio::test]
    async fn verified_local_root_hash_uses_final_versioned_root_after_rotation() {
        let base = tough_fixture_dir("rotated-root");
        let bootstrap_root = tokio::fs::read(base.join("1.root.json"))
            .await
            .expect("bootstrap root reads");
        let final_root = tokio::fs::read(base.join("2.root.json"))
            .await
            .expect("final root reads");
        let input = LocalTufRepositoryInput {
            root_path: base.join("1.root.json"),
            metadata_dir: base,
            targets_dir: PathBuf::from("unused-targets"),
            datastore_dir: PathBuf::from("unused-datastore"),
            target_name: "unused".to_string(),
        };

        let hash = verified_local_root_sha256(&input.metadata_dir, &bootstrap_root, 2)
            .await
            .expect("root hash resolves");

        assert_eq!(hash, sha256_uri(&final_root));
    }

    #[tokio::test]
    async fn verified_local_root_hash_uses_bootstrap_root_without_rotation() {
        let base = tough_fixture_dir("rotated-root");
        let bootstrap_root = tokio::fs::read(base.join("1.root.json"))
            .await
            .expect("bootstrap root reads");
        let input = LocalTufRepositoryInput {
            root_path: base.join("1.root.json"),
            metadata_dir: base,
            targets_dir: PathBuf::from("unused-targets"),
            datastore_dir: PathBuf::from("unused-datastore"),
            target_name: "unused".to_string(),
        };

        let hash = verified_local_root_sha256(&input.metadata_dir, &bootstrap_root, 1)
            .await
            .expect("root hash resolves");

        assert_eq!(hash, sha256_uri(&bootstrap_root));
    }
}
