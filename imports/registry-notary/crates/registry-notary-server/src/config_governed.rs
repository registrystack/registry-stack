// SPDX-License-Identifier: Apache-2.0
//! Governed configuration bundle verification shared by admin and CLI paths.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

use registry_notary_core::{ConfigTrustConfig, StandaloneRegistryNotaryConfig};
use registry_platform_config::{
    LocalTufRepositoryInput, RemoteTufRepositoryInput, TufConfigVerifier, VerificationContext,
};
use registry_platform_ops::{internal_config_hash, ConfigSource};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct ConfigGovernanceContext {
    pub(crate) instance_id: String,
    pub(crate) environment: String,
    pub(crate) config_trust: Option<ConfigTrustConfig>,
}

impl ConfigGovernanceContext {
    #[must_use]
    pub fn from_config(config: &StandaloneRegistryNotaryConfig) -> Self {
        Self {
            instance_id: config.instance.id.clone(),
            environment: config.instance.environment.clone(),
            config_trust: config.config_trust.clone(),
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    #[must_use]
    pub fn config_trust(&self) -> Option<&ConfigTrustConfig> {
        self.config_trust.as_ref()
    }
}

impl Default for ConfigGovernanceContext {
    fn default() -> Self {
        Self {
            instance_id: "registry-notary-standalone".to_string(),
            environment: "development".to_string(),
            config_trust: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TufConfigTargetRequest {
    Local(LocalTufConfigTargetRequest),
    Remote(RemoteTufConfigTargetRequest),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTufConfigTargetRequest {
    pub root_path: PathBuf,
    pub metadata_dir: PathBuf,
    pub targets_dir: PathBuf,
    pub datastore_dir: PathBuf,
    pub target_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteTufConfigTargetRequest {
    pub root_path: PathBuf,
    pub metadata_base_url: String,
    pub targets_base_url: String,
    pub datastore_dir: PathBuf,
    pub target_name: String,
    #[serde(default)]
    pub allow_dev_insecure_fetch_urls: bool,
}

pub struct ResolvedConfigCandidate {
    pub bundle_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub previous_config_hash: Option<String>,
    pub root_version: Option<u64>,
    pub change_classes: BTreeSet<String>,
    pub signer_kids: BTreeSet<String>,
    pub tuf_root_sha256: Option<String>,
    pub config_yaml: String,
    pub(crate) source: ConfigSource,
}

impl ResolvedConfigCandidate {
    #[must_use]
    pub fn source_label(&self) -> &'static str {
        self.source.as_posture_str()
    }

    #[must_use]
    pub fn internal_config_hash(&self) -> String {
        internal_config_hash(self.config_yaml.as_bytes())
    }
}

#[derive(Debug)]
pub enum ConfigCandidateError {
    CandidateInvalid(&'static str),
    BundleInvalid(&'static str),
}

impl ConfigCandidateError {
    #[must_use]
    pub fn detail(&self) -> &'static str {
        match self {
            Self::CandidateInvalid(detail) | Self::BundleInvalid(detail) => detail,
        }
    }
}

impl fmt::Display for ConfigCandidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail())
    }
}

impl StdError for ConfigCandidateError {}

pub async fn resolve_tuf_config_candidate(
    request: &TufConfigTargetRequest,
    governance: &ConfigGovernanceContext,
) -> Result<ResolvedConfigCandidate, ConfigCandidateError> {
    let Some(config_trust) = governance.config_trust() else {
        return Err(ConfigCandidateError::BundleInvalid(
            "signed config trust roots are not configured",
        ));
    };
    if config_trust.accepted_roots.is_empty() {
        return Err(ConfigCandidateError::BundleInvalid(
            "signed config trust roots are not configured",
        ));
    }
    let context = VerificationContext {
        product: "registry-notary".to_string(),
        instance_id: governance.instance_id().to_string(),
        environment: governance.environment().to_string(),
    };
    let (verified, source) = match request {
        TufConfigTargetRequest::Local(request) => {
            let input = LocalTufRepositoryInput {
                root_path: request.root_path.clone(),
                metadata_dir: request.metadata_dir.clone(),
                targets_dir: request.targets_dir.clone(),
                datastore_dir: request.datastore_dir.clone(),
                target_name: request.target_name.clone(),
            };
            let verified = TufConfigVerifier::verify_config_target(&input, &context)
                .await
                .map_err(|_| {
                    ConfigCandidateError::BundleInvalid(
                        "signed config target could not be verified",
                    )
                })?;
            (verified, ConfigSource::SignedBundleFile)
        }
        TufConfigTargetRequest::Remote(request) => {
            let input = RemoteTufRepositoryInput {
                root_path: request.root_path.clone(),
                metadata_base_url: request.metadata_base_url.clone(),
                targets_base_url: request.targets_base_url.clone(),
                datastore_dir: request.datastore_dir.clone(),
                target_name: request.target_name.clone(),
                allow_dev_insecure_fetch_urls: request.allow_dev_insecure_fetch_urls,
            };
            let verified = TufConfigVerifier::verify_remote_config_target(&input, &context)
                .await
                .map_err(|_| {
                    ConfigCandidateError::BundleInvalid(
                        "signed config target could not be verified",
                    )
                })?;
            (verified, ConfigSource::SignedBundleEndpoint)
        }
    };
    if !config_trust.accepted_roots.iter().any(|root| {
        root.authorize(
            &verified.metadata.change_classes,
            &verified.tuf.signer_kids,
            &verified.tuf.root_sha256,
        )
        .is_ok()
    }) {
        return Err(ConfigCandidateError::BundleInvalid(
            "signed config target was not authorized by local trust roots",
        ));
    }
    let config_yaml = String::from_utf8(verified.tuf.target_bytes).map_err(|_| {
        ConfigCandidateError::CandidateInvalid("candidate config payload is not valid UTF-8")
    })?;
    Ok(ResolvedConfigCandidate {
        bundle_id: verified.metadata.bundle_id,
        stream_id: verified.metadata.stream_id,
        sequence: verified.metadata.sequence,
        previous_config_hash: verified.metadata.previous_config_hash,
        root_version: Some(verified.tuf.root_version),
        change_classes: verified.metadata.change_classes,
        signer_kids: verified.tuf.signer_kids.into_iter().collect(),
        tuf_root_sha256: Some(verified.tuf.root_sha256),
        config_yaml,
        source,
    })
}

#[must_use]
pub fn is_signed_config_source(source: ConfigSource) -> bool {
    matches!(
        source,
        ConfigSource::SignedBundleFile | ConfigSource::SignedBundleEndpoint
    )
}

pub fn parse_candidate_config(
    config_yaml: &str,
) -> Result<StandaloneRegistryNotaryConfig, &'static str> {
    let config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(config_yaml).map_err(|_| "candidate config could not be parsed")?;
    config
        .validate()
        .map_err(|_| "candidate config did not validate")?;
    Ok(config)
}
