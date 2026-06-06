// SPDX-License-Identifier: Apache-2.0
//! Governed configuration bundle verification shared by admin and CLI paths.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

use registry_platform_config::{
    LocalTufRepositoryInput, RemoteTufRepositoryInput, TufConfigVerifier, VerificationContext,
};
use registry_platform_ops::{
    internal_config_hash, posture_safe_runtime_config_hash, ConfigProvenance, ConfigSource,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{self, Config};

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
    pub source: ConfigSource,
}

#[derive(Debug, Serialize)]
pub enum ConfigCandidateError {
    CandidateInvalid(&'static str),
    BundleInvalid(&'static str),
}

impl ConfigCandidateError {
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
    current_config: &Config,
) -> Result<ResolvedConfigCandidate, ConfigCandidateError> {
    let environment = current_config
        .instance
        .environment
        .clone()
        .unwrap_or_else(|| "development".to_string());
    let context = VerificationContext {
        product: "registry-relay".to_string(),
        instance_id: current_config.instance.id.clone(),
        environment,
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

pub fn authorize_signed_config_candidate(
    candidate: &ResolvedConfigCandidate,
    current_config: &Config,
) -> Result<(), ConfigCandidateError> {
    if !is_signed_config_source(candidate.source) {
        return Ok(());
    }
    let Some(config_trust) = &current_config.config_trust else {
        return Err(ConfigCandidateError::BundleInvalid(
            "signed config trust roots are not configured",
        ));
    };
    if config_trust.accepted_roots.is_empty() {
        return Err(ConfigCandidateError::BundleInvalid(
            "signed config trust roots are not configured",
        ));
    }
    let signer_kids = candidate.signer_kids.iter().cloned().collect::<Vec<_>>();
    if config_trust.accepted_roots.iter().any(|root| {
        root.authorize(
            &candidate.change_classes,
            &signer_kids,
            candidate
                .tuf_root_sha256
                .as_deref()
                .unwrap_or("sha256:missing"),
        )
        .is_ok()
    }) {
        Ok(())
    } else {
        Err(ConfigCandidateError::BundleInvalid(
            "signed config target was not authorized by local trust roots",
        ))
    }
}

pub fn is_signed_config_source(source: ConfigSource) -> bool {
    matches!(
        source,
        ConfigSource::SignedBundleFile | ConfigSource::SignedBundleEndpoint
    )
}

pub fn parse_candidate_config_with_provenance(
    config_yaml: &str,
    bundle_id: &str,
    sequence: u64,
    source: ConfigSource,
) -> Result<(Config, ConfigProvenance), &'static str> {
    let config_value: Value =
        serde_saphyr::from_str(config_yaml).map_err(|_| "candidate config could not be parsed")?;
    let config: Config =
        serde_saphyr::from_str(config_yaml).map_err(|_| "candidate config could not be parsed")?;
    config::validate::run(&config).map_err(|_| "candidate config did not validate")?;
    let mut provenance = ConfigProvenance {
        source,
        internal_config_hash: internal_config_hash(config_yaml.as_bytes()),
        posture_config_hash: posture_safe_runtime_config_hash(&config_value),
        dynamic_reload_supported: true,
        last_bundle_id: Some(bundle_id.to_string()),
        last_bundle_sequence: Some(sequence),
        last_apply_result: None,
        last_apply_at: None,
        restart_required: false,
    };
    if bundle_id.trim().is_empty() {
        provenance.last_bundle_id = None;
    }
    Ok((config, provenance))
}
