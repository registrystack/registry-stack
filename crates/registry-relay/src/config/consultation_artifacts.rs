// SPDX-License-Identifier: Apache-2.0
//! Closed startup inputs for governed consultation source-plan compilation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use registry_platform_config::{read_config_file_limited, sha256_uri, VerifiedConfigBundle};
use registry_platform_ops::{is_sha256_config_hash, ConfigSource, DeploymentProfile};
use schemars::JsonSchema;
use serde::Deserialize;
use thiserror::Error;

use super::{Config, ConsultationConfig};

const MAX_TYPED_ARTIFACT_BYTES: u64 = 256 * 1024;
const MAX_EVIDENCE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_FILES_PER_CLASS: usize = 32;
const MAX_EVIDENCE_CLASS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RHAI_SCRIPT_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACTS: usize = 256;
const MAX_ENABLED_PROFILES: usize = 64;
const MAX_TOTAL_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

/// One hash-pinned public contract or reviewed integration pack.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsultationTypedArtifactReferenceConfig {
    /// Normalized bundle-root-relative path.
    pub path: PathBuf,
    /// Domain-separated typed artifact hash consumed by the source-plan compiler.
    #[schemars(pattern(r"^sha256:[0-9a-f]{64}$"))]
    pub hash: String,
    /// Raw file hash recorded by Registry Config Bundle v1.
    #[schemars(pattern(r"^sha256:[0-9a-f]{64}$"))]
    pub sha256: String,
}

impl fmt::Debug for ConsultationTypedArtifactReferenceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsultationTypedArtifactReferenceConfig")
            .field("configured", &true)
            .finish()
    }
}

/// One hash-pinned private binding or standalone Rhai script.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsultationArtifactReferenceConfig {
    /// Normalized bundle-root-relative path.
    pub path: PathBuf,
    /// Raw file hash recorded by Registry Config Bundle v1.
    #[schemars(pattern(r"^sha256:[0-9a-f]{64}$"))]
    pub sha256: String,
}

impl fmt::Debug for ConsultationArtifactReferenceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsultationArtifactReferenceConfig")
            .field("configured", &true)
            .finish()
    }
}

/// Closed evidence classes understood by consultation source-plan v1.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ConsultationEvidenceClassConfig {
    Conformance,
    NegativeSecurity,
    Minimization,
}

/// One bounded, hash-pinned integration evidence file.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsultationEvidenceArtifactConfig {
    pub class: ConsultationEvidenceClassConfig,
    pub path: PathBuf,
    #[schemars(pattern(r"^sha256:[0-9a-f]{64}$"))]
    pub sha256: String,
}

impl fmt::Debug for ConsultationEvidenceArtifactConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsultationEvidenceArtifactConfig")
            .field("class", &self.class)
            .field("configured", &true)
            .finish()
    }
}

/// Complete artifact catalog for all consultations enabled at one restart.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsultationArtifactClosureConfig {
    pub public_contracts: Vec<ConsultationTypedArtifactReferenceConfig>,
    pub integration_packs: Vec<ConsultationTypedArtifactReferenceConfig>,
    pub private_bindings: Vec<ConsultationTypedArtifactReferenceConfig>,
    pub evidence: Vec<ConsultationEvidenceArtifactConfig>,
    #[serde(default)]
    pub rhai_scripts: Vec<ConsultationArtifactReferenceConfig>,
}

impl fmt::Debug for ConsultationArtifactClosureConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsultationArtifactClosureConfig")
            .field("public_contract_count", &self.public_contracts.len())
            .field("integration_pack_count", &self.integration_packs.len())
            .field("private_binding_count", &self.private_bindings.len())
            .field("evidence_count", &self.evidence.len())
            .field("rhai_script_count", &self.rhai_scripts.len())
            .finish()
    }
}

/// Safe, value-free reason that product-level artifact closure failed.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ConsultationArtifactClosureError {
    #[error("consultation artifact configuration is invalid")]
    InvalidConfiguration,
    #[error("non-local consultation activation requires a signed bundle")]
    UnsignedActivation,
    #[error("consultation artifact path is not normalized inside its root")]
    InvalidPath,
    #[error("consultation artifact is duplicated")]
    DuplicateArtifact,
    #[error("consultation artifact is absent from the verified file closure")]
    MissingArtifact,
    #[error("consultation artifact hash does not match its verified reference")]
    HashMismatch,
    #[error("consultation artifact exceeds its class bound")]
    BoundsExceeded,
    #[error("consultation artifact uses an unsupported filesystem object")]
    UnsafeFile,
    #[error("signed config bundle contains an unreferenced runtime file")]
    UnreferencedArtifact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum VerifiedEvidenceClass {
    Conformance,
    NegativeSecurity,
    Minimization,
}

impl From<ConsultationEvidenceClassConfig> for VerifiedEvidenceClass {
    fn from(value: ConsultationEvidenceClassConfig) -> Self {
        match value {
            ConsultationEvidenceClassConfig::Conformance => Self::Conformance,
            ConsultationEvidenceClassConfig::NegativeSecurity => Self::NegativeSecurity,
            ConsultationEvidenceClassConfig::Minimization => Self::Minimization,
        }
    }
}

#[allow(
    dead_code,
    reason = "consumed by the restart-only consultation registry compilation slice"
)]
pub(crate) struct VerifiedTypedConsultationArtifact {
    bytes: Box<[u8]>,
    artifact_hash: Box<str>,
}

#[allow(
    dead_code,
    reason = "consumed by the restart-only consultation registry compilation slice"
)]
impl VerifiedTypedConsultationArtifact {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn artifact_hash(&self) -> &str {
        &self.artifact_hash
    }
}

#[allow(
    dead_code,
    reason = "consumed by the restart-only consultation registry compilation slice"
)]
pub(crate) struct VerifiedConsultationArtifact {
    bytes: Box<[u8]>,
    sha256: Box<str>,
}

#[allow(
    dead_code,
    reason = "consumed by the restart-only consultation registry compilation slice"
)]
impl VerifiedConsultationArtifact {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[allow(
    dead_code,
    reason = "consumed by the restart-only consultation registry compilation slice"
)]
pub(crate) struct VerifiedConsultationEvidenceArtifact {
    class: VerifiedEvidenceClass,
    artifact: VerifiedConsultationArtifact,
}

#[allow(
    dead_code,
    reason = "consumed by the restart-only consultation registry compilation slice"
)]
impl VerifiedConsultationEvidenceArtifact {
    pub(crate) const fn class(&self) -> VerifiedEvidenceClass {
        self.class
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.artifact.bytes()
    }

    pub(crate) fn sha256(&self) -> &str {
        self.artifact.sha256()
    }
}

/// Verified, normalized, bounded bytes accepted by startup compilation.
///
/// Paths and the signed manifest are intentionally discarded. Raw bytes are
/// available only through crate-private accessors and disappear when startup
/// compilation consumes this value.
pub struct VerifiedConsultationArtifactClosure {
    public_contracts: Box<[VerifiedTypedConsultationArtifact]>,
    integration_packs: Box<[VerifiedTypedConsultationArtifact]>,
    private_bindings: Box<[VerifiedTypedConsultationArtifact]>,
    evidence: Box<[VerifiedConsultationEvidenceArtifact]>,
    rhai_scripts: Box<[VerifiedConsultationArtifact]>,
}

impl fmt::Debug for VerifiedConsultationArtifactClosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedConsultationArtifactClosure")
            .field("public_contract_count", &self.public_contracts.len())
            .field("integration_pack_count", &self.integration_packs.len())
            .field("private_binding_count", &self.private_bindings.len())
            .field("evidence_count", &self.evidence.len())
            .field("rhai_script_count", &self.rhai_scripts.len())
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "consumed by the restart-only consultation registry compilation slice"
)]
impl VerifiedConsultationArtifactClosure {
    pub(crate) fn public_contracts(&self) -> &[VerifiedTypedConsultationArtifact] {
        &self.public_contracts
    }

    pub(crate) fn integration_packs(&self) -> &[VerifiedTypedConsultationArtifact] {
        &self.integration_packs
    }

    pub(crate) fn private_bindings(&self) -> &[VerifiedTypedConsultationArtifact] {
        &self.private_bindings
    }

    pub(crate) fn evidence(&self) -> &[VerifiedConsultationEvidenceArtifact] {
        &self.evidence
    }

    pub(crate) fn rhai_scripts(&self) -> &[VerifiedConsultationArtifact] {
        &self.rhai_scripts
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        public_contracts: Vec<(Vec<u8>, String)>,
        integration_packs: Vec<(Vec<u8>, String)>,
        private_bindings: Vec<Vec<u8>>,
        evidence: Vec<(VerifiedEvidenceClass, Vec<u8>, String)>,
        rhai_scripts: Vec<(Vec<u8>, String)>,
    ) -> Self {
        Self {
            public_contracts: public_contracts
                .into_iter()
                .map(|(bytes, hash)| VerifiedTypedConsultationArtifact {
                    bytes: bytes.into_boxed_slice(),
                    artifact_hash: hash.into_boxed_str(),
                })
                .collect(),
            integration_packs: integration_packs
                .into_iter()
                .map(|(bytes, hash)| VerifiedTypedConsultationArtifact {
                    bytes: bytes.into_boxed_slice(),
                    artifact_hash: hash.into_boxed_str(),
                })
                .collect(),
            private_bindings: private_bindings
                .into_iter()
                .map(|bytes| {
                    let authored = crate::source_plan::authoring::compile_private_binding(&bytes)
                        .expect("test private binding compiles");
                    VerifiedTypedConsultationArtifact {
                        artifact_hash: authored.typed_hash().into(),
                        bytes: bytes.into_boxed_slice(),
                    }
                })
                .collect(),
            evidence: evidence
                .into_iter()
                .map(
                    |(class, bytes, hash)| VerifiedConsultationEvidenceArtifact {
                        class,
                        artifact: VerifiedConsultationArtifact {
                            bytes: bytes.into_boxed_slice(),
                            sha256: hash.into_boxed_str(),
                        },
                    },
                )
                .collect(),
            rhai_scripts: rhai_scripts
                .into_iter()
                .map(|(bytes, hash)| VerifiedConsultationArtifact {
                    bytes: bytes.into_boxed_slice(),
                    sha256: hash.into_boxed_str(),
                })
                .collect(),
        }
    }
}

/// Signed bundle file index retained only while product config is loaded.
pub(crate) struct SignedBundleRuntimeFiles {
    root: PathBuf,
    primary_config_path: String,
    files: BTreeMap<String, String>,
}

impl SignedBundleRuntimeFiles {
    pub(crate) fn from_verified(
        verified: &VerifiedConfigBundle,
    ) -> Result<Self, ConsultationArtifactClosureError> {
        let mut primary_matches = verified
            .manifest
            .files
            .iter()
            .filter(|file| file.sha256 == verified.manifest.config_hash);
        let primary_config_path = primary_matches
            .next()
            .and_then(|file| normalized_bundle_path(Path::new(&file.path)).ok())
            .ok_or(ConsultationArtifactClosureError::InvalidConfiguration)?;
        if primary_matches.next().is_some() {
            return Err(ConsultationArtifactClosureError::DuplicateArtifact);
        }
        let mut files = BTreeMap::new();
        for file in &verified.manifest.files {
            let path = normalized_bundle_path(Path::new(&file.path))?;
            if files.insert(path, file.sha256.clone()).is_some() {
                return Err(ConsultationArtifactClosureError::DuplicateArtifact);
            }
        }
        let component_count = Path::new(&primary_config_path).components().count();
        let root = verified
            .config_path
            .ancestors()
            .nth(component_count)
            .ok_or(ConsultationArtifactClosureError::InvalidPath)?
            .to_path_buf();
        if root.join(&primary_config_path) != verified.config_path {
            return Err(ConsultationArtifactClosureError::InvalidPath);
        }
        Ok(Self {
            root,
            primary_config_path,
            files,
        })
    }

    pub(crate) fn resolve_metadata_path(
        &self,
        target: &Path,
    ) -> Result<PathBuf, ConsultationArtifactClosureError> {
        let bundle_path = self.metadata_bundle_path(target)?;
        self.files
            .contains_key(&bundle_path)
            .then(|| self.root.join(bundle_path))
            .ok_or(ConsultationArtifactClosureError::MissingArtifact)
    }

    fn metadata_bundle_path(
        &self,
        target: &Path,
    ) -> Result<String, ConsultationArtifactClosureError> {
        if target.is_absolute() {
            return Err(ConsultationArtifactClosureError::InvalidPath);
        }
        let mut path = PathBuf::from(&self.primary_config_path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        path.push(target);
        normalize_joined_bundle_path(&path)
    }

    fn artifact_path(
        &self,
        configured: &str,
        expected_sha256: &str,
    ) -> Result<PathBuf, ConsultationArtifactClosureError> {
        let bundle_path = self.metadata_bundle_path(Path::new(configured))?;
        match self.files.get(&bundle_path) {
            Some(actual) if actual == expected_sha256 => Ok(self.root.join(bundle_path)),
            Some(_) => Err(ConsultationArtifactClosureError::HashMismatch),
            None => Err(ConsultationArtifactClosureError::MissingArtifact),
        }
    }

    pub(crate) fn validate_runtime_closure(
        &self,
        config: &Config,
    ) -> Result<(), ConsultationArtifactClosureError> {
        let mut referenced = BTreeSet::from([self.primary_config_path.clone()]);
        if let Some(metadata) = &config.metadata {
            referenced.insert(self.metadata_bundle_path(&metadata.source.path)?);
        }
        if let Some(artifacts) = config
            .consultation
            .as_ref()
            .and_then(|consultation| consultation.artifacts.as_ref())
        {
            for path in artifacts.paths() {
                referenced.insert(self.metadata_bundle_path(path)?);
            }
        }
        let present = self.files.keys().cloned().collect::<BTreeSet<_>>();
        if present != referenced {
            return if referenced.iter().any(|path| !present.contains(path)) {
                Err(ConsultationArtifactClosureError::MissingArtifact)
            } else {
                Err(ConsultationArtifactClosureError::UnreferencedArtifact)
            };
        }
        Ok(())
    }
}

impl ConsultationArtifactClosureConfig {
    fn paths(&self) -> impl Iterator<Item = &Path> {
        self.public_contracts
            .iter()
            .map(|artifact| artifact.path.as_path())
            .chain(
                self.integration_packs
                    .iter()
                    .map(|artifact| artifact.path.as_path()),
            )
            .chain(
                self.private_bindings
                    .iter()
                    .map(|artifact| artifact.path.as_path()),
            )
            .chain(self.evidence.iter().map(|artifact| artifact.path.as_path()))
            .chain(
                self.rhai_scripts
                    .iter()
                    .map(|artifact| artifact.path.as_path()),
            )
    }

    pub(crate) fn validate_shape(&self) -> Result<(), ConsultationArtifactClosureError> {
        if self.public_contracts.is_empty()
            || self.public_contracts.len() > MAX_ENABLED_PROFILES
            || self.integration_packs.is_empty()
            || self.integration_packs.len() > MAX_ENABLED_PROFILES
            || self.private_bindings.is_empty()
            || self.private_bindings.len() > MAX_ENABLED_PROFILES
        {
            return Err(ConsultationArtifactClosureError::InvalidConfiguration);
        }
        let total = self
            .public_contracts
            .len()
            .checked_add(self.integration_packs.len())
            .and_then(|count| count.checked_add(self.private_bindings.len()))
            .and_then(|count| count.checked_add(self.evidence.len()))
            .and_then(|count| count.checked_add(self.rhai_scripts.len()))
            .ok_or(ConsultationArtifactClosureError::BoundsExceeded)?;
        if total > MAX_ARTIFACTS {
            return Err(ConsultationArtifactClosureError::BoundsExceeded);
        }
        let mut paths = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for artifact in &self.public_contracts {
            validate_typed_reference(artifact, &mut paths, &mut hashes)?;
        }
        for artifact in &self.integration_packs {
            validate_typed_reference(artifact, &mut paths, &mut hashes)?;
        }
        for artifact in &self.private_bindings {
            validate_typed_reference(artifact, &mut paths, &mut hashes)?;
        }
        for artifact in &self.evidence {
            validate_reference_parts(&artifact.path, &artifact.sha256, &mut paths, &mut hashes)?;
        }
        for artifact in &self.rhai_scripts {
            validate_file_reference(artifact, &mut paths, &mut hashes)?;
        }
        Ok(())
    }
}

fn validate_typed_reference(
    artifact: &ConsultationTypedArtifactReferenceConfig,
    paths: &mut BTreeSet<String>,
    hashes: &mut BTreeSet<String>,
) -> Result<(), ConsultationArtifactClosureError> {
    if !is_sha256_config_hash(&artifact.hash) {
        return Err(ConsultationArtifactClosureError::InvalidConfiguration);
    }
    validate_reference_parts(&artifact.path, &artifact.sha256, paths, hashes)
}

fn validate_file_reference(
    artifact: &ConsultationArtifactReferenceConfig,
    paths: &mut BTreeSet<String>,
    hashes: &mut BTreeSet<String>,
) -> Result<(), ConsultationArtifactClosureError> {
    validate_reference_parts(&artifact.path, &artifact.sha256, paths, hashes)
}

fn validate_reference_parts(
    path: &Path,
    sha256: &str,
    paths: &mut BTreeSet<String>,
    hashes: &mut BTreeSet<String>,
) -> Result<(), ConsultationArtifactClosureError> {
    if !is_sha256_config_hash(sha256) {
        return Err(ConsultationArtifactClosureError::InvalidConfiguration);
    }
    let normalized = normalized_bundle_path(path)?;
    if !paths.insert(normalized) || !hashes.insert(sha256.to_owned()) {
        return Err(ConsultationArtifactClosureError::DuplicateArtifact);
    }
    Ok(())
}

pub(crate) fn validate_consultation_artifact_config(
    consultation: &ConsultationConfig,
) -> Result<(), ConsultationArtifactClosureError> {
    match &consultation.artifacts {
        Some(artifacts) => artifacts.validate_shape(),
        None => Ok(()),
    }
}

pub(crate) fn load_consultation_artifacts(
    config_path: &Path,
    config: &Config,
    source: ConfigSource,
    signed_files: Option<&SignedBundleRuntimeFiles>,
) -> Result<Option<VerifiedConsultationArtifactClosure>, ConsultationArtifactClosureError> {
    if let Some(signed_files) = signed_files {
        signed_files.validate_runtime_closure(config)?;
    }
    let Some(closure) = config
        .consultation
        .as_ref()
        .and_then(|consultation| consultation.artifacts.as_ref())
    else {
        return Ok(None);
    };
    closure.validate_shape()?;
    let signed = source == ConfigSource::SignedBundleFile;
    if !signed && config.deployment.profile != Some(DeploymentProfile::Local) {
        return Err(ConsultationArtifactClosureError::UnsignedActivation);
    }
    let local_root = config_path.parent().unwrap_or_else(|| Path::new("."));
    let mut total_bytes = 0_u64;
    let public_contracts = closure
        .public_contracts
        .iter()
        .map(|artifact| {
            let bytes = load_artifact(
                artifact.path.as_path(),
                &artifact.sha256,
                MAX_TYPED_ARTIFACT_BYTES,
                local_root,
                signed_files,
                &mut total_bytes,
            )?;
            Ok(VerifiedTypedConsultationArtifact {
                bytes,
                artifact_hash: artifact.hash.clone().into_boxed_str(),
            })
        })
        .collect::<Result<_, ConsultationArtifactClosureError>>()?;
    let integration_packs = closure
        .integration_packs
        .iter()
        .map(|artifact| {
            let bytes = load_artifact(
                artifact.path.as_path(),
                &artifact.sha256,
                MAX_TYPED_ARTIFACT_BYTES,
                local_root,
                signed_files,
                &mut total_bytes,
            )?;
            Ok(VerifiedTypedConsultationArtifact {
                bytes,
                artifact_hash: artifact.hash.clone().into_boxed_str(),
            })
        })
        .collect::<Result<_, ConsultationArtifactClosureError>>()?;
    let private_bindings = closure
        .private_bindings
        .iter()
        .map(|artifact| {
            let bytes = load_artifact(
                artifact.path.as_path(),
                &artifact.sha256,
                MAX_TYPED_ARTIFACT_BYTES,
                local_root,
                signed_files,
                &mut total_bytes,
            )?;
            let authored = crate::source_plan::authoring::compile_private_binding(&bytes)
                .map_err(|_| ConsultationArtifactClosureError::HashMismatch)?;
            if authored.typed_hash() != artifact.hash {
                return Err(ConsultationArtifactClosureError::HashMismatch);
            }
            Ok(VerifiedTypedConsultationArtifact {
                bytes,
                artifact_hash: artifact.hash.clone().into_boxed_str(),
            })
        })
        .collect::<Result<_, ConsultationArtifactClosureError>>()?;
    let mut class_counts = BTreeMap::<ConsultationEvidenceClassConfig, usize>::new();
    let mut class_bytes = BTreeMap::<ConsultationEvidenceClassConfig, u64>::new();
    let evidence = closure
        .evidence
        .iter()
        .map(|artifact| {
            let bytes = load_artifact(
                artifact.path.as_path(),
                &artifact.sha256,
                MAX_EVIDENCE_FILE_BYTES,
                local_root,
                signed_files,
                &mut total_bytes,
            )?;
            let count = class_counts.entry(artifact.class).or_default();
            *count += 1;
            let byte_count = class_bytes.entry(artifact.class).or_default();
            *byte_count = byte_count
                .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .ok_or(ConsultationArtifactClosureError::BoundsExceeded)?;
            if *count > MAX_EVIDENCE_FILES_PER_CLASS || *byte_count > MAX_EVIDENCE_CLASS_BYTES {
                return Err(ConsultationArtifactClosureError::BoundsExceeded);
            }
            Ok(VerifiedConsultationEvidenceArtifact {
                class: artifact.class.into(),
                artifact: VerifiedConsultationArtifact {
                    bytes,
                    sha256: artifact.sha256.clone().into_boxed_str(),
                },
            })
        })
        .collect::<Result<_, ConsultationArtifactClosureError>>()?;
    let rhai_scripts = closure
        .rhai_scripts
        .iter()
        .map(|artifact| {
            load_file_artifact(
                artifact,
                MAX_RHAI_SCRIPT_BYTES,
                local_root,
                signed_files,
                &mut total_bytes,
            )
        })
        .collect::<Result<_, _>>()?;
    Ok(Some(VerifiedConsultationArtifactClosure {
        public_contracts,
        integration_packs,
        private_bindings,
        evidence,
        rhai_scripts,
    }))
}

fn load_file_artifact(
    artifact: &ConsultationArtifactReferenceConfig,
    max_bytes: u64,
    local_root: &Path,
    signed_files: Option<&SignedBundleRuntimeFiles>,
    total_bytes: &mut u64,
) -> Result<VerifiedConsultationArtifact, ConsultationArtifactClosureError> {
    Ok(VerifiedConsultationArtifact {
        bytes: load_artifact(
            &artifact.path,
            &artifact.sha256,
            max_bytes,
            local_root,
            signed_files,
            total_bytes,
        )?,
        sha256: artifact.sha256.clone().into_boxed_str(),
    })
}

fn load_artifact(
    configured_path: &Path,
    expected_sha256: &str,
    max_bytes: u64,
    local_root: &Path,
    signed_files: Option<&SignedBundleRuntimeFiles>,
    total_bytes: &mut u64,
) -> Result<Box<[u8]>, ConsultationArtifactClosureError> {
    let normalized = normalized_bundle_path(configured_path)?;
    let path = match signed_files {
        Some(files) => files.artifact_path(&normalized, expected_sha256)?,
        None => local_root.join(&normalized),
    };
    reject_symlink_components(
        signed_files.map_or(local_root, |files| files.root.as_path()),
        &path,
    )?;
    if fs::metadata(&path)
        .map_err(|_| ConsultationArtifactClosureError::MissingArtifact)?
        .len()
        > max_bytes
    {
        return Err(ConsultationArtifactClosureError::BoundsExceeded);
    }
    let bytes = read_config_file_limited(&path, max_bytes).map_err(|error| match error {
        registry_platform_config::ConfigBundleError::Io(_)
        | registry_platform_config::ConfigBundleError::FileClosure(_) => {
            ConsultationArtifactClosureError::MissingArtifact
        }
        _ => ConsultationArtifactClosureError::BoundsExceeded,
    })?;
    if sha256_uri(&bytes) != expected_sha256 {
        return Err(ConsultationArtifactClosureError::HashMismatch);
    }
    *total_bytes = total_bytes
        .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        .ok_or(ConsultationArtifactClosureError::BoundsExceeded)?;
    if *total_bytes > MAX_TOTAL_ARTIFACT_BYTES {
        return Err(ConsultationArtifactClosureError::BoundsExceeded);
    }
    Ok(bytes.into_boxed_slice())
}

fn reject_symlink_components(
    root: &Path,
    path: &Path,
) -> Result<(), ConsultationArtifactClosureError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ConsultationArtifactClosureError::InvalidPath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(ConsultationArtifactClosureError::InvalidPath);
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| ConsultationArtifactClosureError::MissingArtifact)?;
        if metadata.file_type().is_symlink() {
            return Err(ConsultationArtifactClosureError::UnsafeFile);
        }
    }
    let metadata =
        fs::metadata(path).map_err(|_| ConsultationArtifactClosureError::MissingArtifact)?;
    if !metadata.is_file() {
        return Err(ConsultationArtifactClosureError::UnsafeFile);
    }
    Ok(())
}

fn normalized_bundle_path(path: &Path) -> Result<String, ConsultationArtifactClosureError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(ConsultationArtifactClosureError::InvalidPath);
    }
    let text = path
        .to_str()
        .ok_or(ConsultationArtifactClosureError::InvalidPath)?;
    if text.contains('\\') {
        return Err(ConsultationArtifactClosureError::InvalidPath);
    }
    if text
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ConsultationArtifactClosureError::InvalidPath);
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or(ConsultationArtifactClosureError::InvalidPath)?,
            ),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(ConsultationArtifactClosureError::InvalidPath),
        }
    }
    if parts.is_empty() {
        return Err(ConsultationArtifactClosureError::InvalidPath);
    }
    Ok(parts.join("/"))
}

fn normalize_joined_bundle_path(path: &Path) -> Result<String, ConsultationArtifactClosureError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or(ConsultationArtifactClosureError::InvalidPath)?
                    .to_owned(),
            ),
            Component::CurDir => {}
            Component::ParentDir => {
                parts
                    .pop()
                    .ok_or(ConsultationArtifactClosureError::InvalidPath)?;
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(ConsultationArtifactClosureError::InvalidPath)
            }
        }
    }
    if parts.is_empty() {
        return Err(ConsultationArtifactClosureError::InvalidPath);
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use registry_platform_ops::DeploymentProfile;
    use serde_json::json;

    use super::*;
    use tempfile::TempDir;

    fn hash(byte: u8) -> String {
        format!("sha256:{byte:064x}")
    }

    fn typed(path: &str, byte: u8) -> ConsultationTypedArtifactReferenceConfig {
        ConsultationTypedArtifactReferenceConfig {
            path: path.into(),
            hash: hash(byte.saturating_add(10)),
            sha256: hash(byte),
        }
    }

    fn closure() -> ConsultationArtifactClosureConfig {
        ConsultationArtifactClosureConfig {
            public_contracts: vec![typed("consultation/contracts/example.json", 1)],
            integration_packs: vec![typed("consultation/packs/example.json", 2)],
            private_bindings: vec![typed("consultation/bindings/example.json", 3)],
            evidence: vec![ConsultationEvidenceArtifactConfig {
                class: ConsultationEvidenceClassConfig::Conformance,
                path: "consultation/evidence/example.txt".into(),
                sha256: hash(4),
            }],
            rhai_scripts: Vec::new(),
        }
    }

    #[test]
    fn artifact_paths_and_entries_are_closed_and_bounded() {
        let valid = closure();
        valid.validate_shape().expect("valid closure shape");
        let debug = format!("{valid:?}");
        assert!(!debug.contains("consultation/"));
        assert!(!debug.contains(&hash(1)));
        assert!(debug.contains("public_contract_count: 1"));

        let mut duplicate = closure();
        duplicate.private_bindings[0].path = duplicate.public_contracts[0].path.clone();
        assert_eq!(
            duplicate.validate_shape(),
            Err(ConsultationArtifactClosureError::DuplicateArtifact)
        );

        for invalid in [
            "../escape.json",
            "/absolute.json",
            "a/./b.json",
            "a\\b.json",
        ] {
            let mut invalid_closure = closure();
            invalid_closure.public_contracts[0].path = invalid.into();
            assert_eq!(
                invalid_closure.validate_shape(),
                Err(ConsultationArtifactClosureError::InvalidPath)
            );
        }

        let mut too_many = closure();
        too_many.public_contracts = (0..=MAX_ENABLED_PROFILES)
            .map(|index| {
                typed(
                    &format!("contracts/{index}.json"),
                    u8::try_from(index).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            too_many.validate_shape(),
            Err(ConsultationArtifactClosureError::InvalidConfiguration)
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_artifact_reads_reject_symlinks_and_oversized_files() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target.json");
        fs::write(&target, b"{}").unwrap();
        let link = temp.path().join("link.json");
        symlink(&target, &link).unwrap();
        assert_eq!(
            reject_symlink_components(temp.path(), &link),
            Err(ConsultationArtifactClosureError::UnsafeFile)
        );

        let oversized = temp.path().join("oversized.rhai");
        fs::write(&oversized, vec![b'x'; MAX_RHAI_SCRIPT_BYTES as usize + 1]).unwrap();
        let mut total = 0;
        assert_eq!(
            load_artifact(
                Path::new("oversized.rhai"),
                &sha256_uri(&fs::read(&oversized).unwrap()),
                MAX_RHAI_SCRIPT_BYTES,
                temp.path(),
                None,
                &mut total,
            ),
            Err(ConsultationArtifactClosureError::BoundsExceeded)
        );
    }

    #[test]
    fn artifact_reads_reject_missing_hash_mismatch_and_non_files() {
        let temp = TempDir::new().unwrap();
        let artifact = temp.path().join("artifact.json");
        fs::write(&artifact, b"{}").unwrap();

        let mut total = 0;
        assert_eq!(
            load_artifact(
                Path::new("missing.json"),
                &sha256_uri(b"{}"),
                MAX_TYPED_ARTIFACT_BYTES,
                temp.path(),
                None,
                &mut total,
            ),
            Err(ConsultationArtifactClosureError::MissingArtifact)
        );
        assert_eq!(
            load_artifact(
                Path::new("artifact.json"),
                &sha256_uri(b"different"),
                MAX_TYPED_ARTIFACT_BYTES,
                temp.path(),
                None,
                &mut total,
            ),
            Err(ConsultationArtifactClosureError::HashMismatch)
        );
        assert_eq!(
            reject_symlink_components(temp.path(), temp.path()),
            Err(ConsultationArtifactClosureError::UnsafeFile)
        );
    }

    #[test]
    fn signed_runtime_file_closure_is_exact_and_bundle_local() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "signed-runtime-closure-test-secret",
        );
        config.metadata = None;
        config.consultation = None;
        let signed_files = SignedBundleRuntimeFiles {
            root: PathBuf::from("/bundle"),
            primary_config_path: "config/relay.yaml".to_string(),
            files: BTreeMap::from([
                ("config/relay.yaml".to_string(), hash(1)),
                ("unreferenced.json".to_string(), hash(2)),
            ]),
        };
        assert_eq!(
            signed_files.validate_runtime_closure(&config),
            Err(ConsultationArtifactClosureError::UnreferencedArtifact)
        );

        assert_eq!(
            signed_files.metadata_bundle_path(Path::new("../../escape.yaml")),
            Err(ConsultationArtifactClosureError::InvalidPath)
        );
        assert_eq!(
            signed_files
                .metadata_bundle_path(Path::new("../metadata/manifest.yaml"))
                .unwrap(),
            "metadata/manifest.yaml"
        );

        let artifact_hash = hash(3);
        let signed_files = SignedBundleRuntimeFiles {
            root: PathBuf::from("/bundle"),
            primary_config_path: "config/relay.yaml".to_string(),
            files: BTreeMap::from([
                ("config/relay.yaml".to_string(), hash(1)),
                (
                    "config/artifacts/pack.json".to_string(),
                    artifact_hash.clone(),
                ),
            ]),
        };
        assert_eq!(
            signed_files
                .artifact_path("artifacts/pack.json", &artifact_hash)
                .unwrap(),
            PathBuf::from("/bundle/config/artifacts/pack.json")
        );
        assert_eq!(
            signed_files.artifact_path("../artifacts/pack.json", &artifact_hash),
            Err(ConsultationArtifactClosureError::MissingArtifact)
        );
    }

    #[test]
    fn unsigned_consultation_activation_is_local_development_only() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "unsigned-consultation-test-secret",
        );
        config.deployment.profile = Some(DeploymentProfile::Production);
        config.consultation = Some(
            serde_json::from_value(json!({
                "authorized_workload": {
                    "audience": "relay-consultation",
                    "client_claim_selector": "azp",
                    "client_value": "registry-notary",
                    "principal_id": "registry-notary"
                },
                "state_plane": {
                    "database_url_env": "REGISTRY_RELAY_STATE_DATABASE_URL",
                    "chain_key_epoch_id": "chain-epoch-1",
                    "serving_fence_lock_key": 7_221_091_441_i64,
                    "audit_pseudonym_keyring_lock_key": 7_221_091_442_i64
                },
                "audit_pseudonym_materials": [{
                    "key_id": "epoch-test",
                    "source": {
                        "provider": "environment",
                        "name": "REGISTRY_RELAY_TEST_PSEUDONYM_SECRET"
                    }
                }],
                "artifacts": {
                    "public_contracts": [{
                        "path": "contracts/example.json",
                        "hash": hash(11),
                        "sha256": hash(1)
                    }],
                    "integration_packs": [{
                        "path": "packs/example.json",
                        "hash": hash(12),
                        "sha256": hash(2)
                    }],
                    "private_bindings": [{
                        "path": "bindings/example.json",
                        "hash": hash(13),
                        "sha256": hash(3)
                    }],
                    "evidence": [{
                        "class": "conformance",
                        "path": "evidence/example.txt",
                        "sha256": hash(4)
                    }]
                }
            }))
            .unwrap(),
        );
        assert!(matches!(
            load_consultation_artifacts(
                Path::new("/deployment/relay.yaml"),
                &config,
                ConfigSource::LocalFile,
                None,
            ),
            Err(ConsultationArtifactClosureError::UnsignedActivation)
        ));
    }
}
