// SPDX-License-Identifier: Apache-2.0
//! Governed configuration bundle verification shared by admin and CLI paths.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

use registry_manifest_core::{self as metadata_core, CompiledMetadata, MetadataManifest};
use registry_platform_config::{
    LocalTufRepositoryInput, RemoteTufRepositoryInput, TufConfigVerifier, VerificationContext,
};
use registry_platform_ops::{
    internal_config_hash, posture_safe_runtime_config_hash, ConfigProvenance, ConfigSource,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{self, Config, RemoteTufRepositoryConfig};

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
    /// Deprecated request field retained for old clients. Remote fetch policy
    /// is taken only from `config_trust.remote_tuf_repositories`.
    #[serde(default)]
    pub allow_dev_insecure_fetch_urls: bool,
}

#[derive(Debug, Clone)]
struct AuthorizedRemoteTufConfigTarget {
    root_path: PathBuf,
    metadata_base_url: String,
    targets_base_url: String,
    datastore_dir: PathBuf,
    target_name: String,
    allow_dev_insecure_fetch_urls: bool,
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
    pub metadata_yaml: Option<String>,
    pub metadata_source_digest: Option<String>,
    pub package_digest: Option<String>,
    pub source: ConfigSource,
}

pub struct ParsedConfigCandidate {
    pub config: Config,
    pub provenance: ConfigProvenance,
    pub metadata: Option<CompiledMetadata>,
    pub metadata_source_digest: Option<String>,
    pub package_digest: Option<String>,
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
    let (verified, metadata_yaml, source) = match request {
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
            let metadata_yaml = resolve_local_metadata_target(request, &verified).await?;
            validate_local_package_index_target(request, &verified).await?;
            (verified, metadata_yaml, ConfigSource::SignedBundleFile)
        }
        TufConfigTargetRequest::Remote(request) => {
            let request = authorize_remote_tuf_config_request(request, current_config)?;
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
            let metadata_yaml = resolve_remote_metadata_target(&request, &verified).await?;
            validate_remote_package_index_target(&request, &verified).await?;
            (verified, metadata_yaml, ConfigSource::SignedBundleEndpoint)
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
        metadata_yaml,
        metadata_source_digest: verified.metadata.source_manifest_digest,
        package_digest: verified.metadata.package_digest,
        source,
    })
}

fn authorize_remote_tuf_config_request(
    request: &RemoteTufConfigTargetRequest,
    current_config: &Config,
) -> Result<AuthorizedRemoteTufConfigTarget, ConfigCandidateError> {
    let Some(config_trust) = &current_config.config_trust else {
        return Err(ConfigCandidateError::BundleInvalid(
            "remote signed config repositories are not configured",
        ));
    };
    let Some(allowed) = config_trust
        .remote_tuf_repositories
        .iter()
        .find(|allowed| remote_tuf_source_matches(allowed, request))
    else {
        return Err(ConfigCandidateError::BundleInvalid(
            "remote signed config repository is not authorized",
        ));
    };
    Ok(AuthorizedRemoteTufConfigTarget {
        root_path: allowed.root_path.clone(),
        metadata_base_url: allowed.metadata_base_url.clone(),
        targets_base_url: allowed.targets_base_url.clone(),
        datastore_dir: allowed.datastore_dir.clone(),
        target_name: request.target_name.clone(),
        allow_dev_insecure_fetch_urls: allowed.allow_dev_insecure_fetch_urls,
    })
}

fn remote_tuf_source_matches(
    allowed: &RemoteTufRepositoryConfig,
    request: &RemoteTufConfigTargetRequest,
) -> bool {
    allowed.root_path == request.root_path
        && allowed.metadata_base_url == request.metadata_base_url
        && allowed.targets_base_url == request.targets_base_url
        && allowed.datastore_dir == request.datastore_dir
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
    let candidate = ResolvedConfigCandidate {
        bundle_id: bundle_id.to_string(),
        stream_id: "default".to_string(),
        sequence,
        previous_config_hash: None,
        root_version: None,
        change_classes: BTreeSet::new(),
        signer_kids: BTreeSet::new(),
        tuf_root_sha256: None,
        config_yaml: config_yaml.to_string(),
        metadata_yaml: None,
        metadata_source_digest: None,
        package_digest: None,
        source,
    };
    let parsed = parse_resolved_config_candidate_with_provenance(&candidate)?;
    Ok((parsed.config, parsed.provenance))
}

pub fn parse_resolved_config_candidate_with_provenance(
    candidate: &ResolvedConfigCandidate,
) -> Result<ParsedConfigCandidate, &'static str> {
    let config_value: Value = serde_saphyr::from_str(&candidate.config_yaml)
        .map_err(|_| "candidate config could not be parsed")?;
    let config: Config = serde_saphyr::from_str(&candidate.config_yaml)
        .map_err(|_| "candidate config could not be parsed")?;
    config::validate::run(&config).map_err(|_| "candidate config did not validate")?;
    let (metadata, metadata_source_digest) = parse_candidate_metadata(&config, candidate)?;
    let package_digest = candidate.package_digest.clone();
    let internal_hash = if metadata_source_digest.is_some() || package_digest.is_some() {
        runtime_package_digest(
            &candidate.config_yaml,
            &config,
            metadata_source_digest.as_deref(),
            package_digest.as_deref(),
            candidate.source,
        )?
    } else {
        internal_config_hash(candidate.config_yaml.as_bytes())
    };
    let mut provenance = ConfigProvenance {
        source: candidate.source,
        internal_config_hash: internal_hash.clone(),
        posture_config_hash: posture_safe_runtime_config_hash(&config_value),
        dynamic_reload_supported: true,
        last_bundle_id: Some(candidate.bundle_id.clone()),
        last_bundle_sequence: Some(candidate.sequence),
        last_apply_result: None,
        last_apply_at: None,
        restart_required: false,
    };
    if candidate.bundle_id.trim().is_empty() {
        provenance.last_bundle_id = None;
    }
    Ok(ParsedConfigCandidate {
        config,
        provenance,
        metadata,
        metadata_source_digest,
        package_digest,
    })
}

async fn resolve_local_metadata_target(
    request: &LocalTufConfigTargetRequest,
    verified: &registry_platform_config::VerifiedConfigTarget,
) -> Result<Option<String>, ConfigCandidateError> {
    let Some(target_name) = verified.metadata.metadata_target_name.as_deref() else {
        return Ok(None);
    };
    let input = LocalTufRepositoryInput {
        root_path: request.root_path.clone(),
        metadata_dir: request.metadata_dir.clone(),
        targets_dir: request.targets_dir.clone(),
        datastore_dir: request.datastore_dir.clone(),
        target_name: target_name.to_string(),
    };
    let target = TufConfigVerifier::verify_local_target(&input)
        .await
        .map_err(|_| {
            ConfigCandidateError::BundleInvalid("metadata target could not be verified")
        })?;
    let metadata_yaml = String::from_utf8(target.target_bytes).map_err(|_| {
        ConfigCandidateError::CandidateInvalid("metadata target payload is not valid UTF-8")
    })?;
    validate_metadata_source_digest_claim(
        &metadata_yaml,
        verified.metadata.source_manifest_digest.as_deref(),
    )?;
    Ok(Some(metadata_yaml))
}

async fn resolve_remote_metadata_target(
    request: &AuthorizedRemoteTufConfigTarget,
    verified: &registry_platform_config::VerifiedConfigTarget,
) -> Result<Option<String>, ConfigCandidateError> {
    let Some(target_name) = verified.metadata.metadata_target_name.as_deref() else {
        return Ok(None);
    };
    let input = RemoteTufRepositoryInput {
        root_path: request.root_path.clone(),
        metadata_base_url: request.metadata_base_url.clone(),
        targets_base_url: request.targets_base_url.clone(),
        datastore_dir: request.datastore_dir.clone(),
        target_name: target_name.to_string(),
        allow_dev_insecure_fetch_urls: request.allow_dev_insecure_fetch_urls,
    };
    let target = TufConfigVerifier::verify_remote_target(&input)
        .await
        .map_err(|_| {
            ConfigCandidateError::BundleInvalid("metadata target could not be verified")
        })?;
    let metadata_yaml = String::from_utf8(target.target_bytes).map_err(|_| {
        ConfigCandidateError::CandidateInvalid("metadata target payload is not valid UTF-8")
    })?;
    validate_metadata_source_digest_claim(
        &metadata_yaml,
        verified.metadata.source_manifest_digest.as_deref(),
    )?;
    Ok(Some(metadata_yaml))
}

async fn validate_local_package_index_target(
    request: &LocalTufConfigTargetRequest,
    verified: &registry_platform_config::VerifiedConfigTarget,
) -> Result<(), ConfigCandidateError> {
    let Some(target_name) = verified.metadata.package_index_target_name.as_deref() else {
        return validate_no_unbound_package_digest(verified);
    };
    let input = LocalTufRepositoryInput {
        root_path: request.root_path.clone(),
        metadata_dir: request.metadata_dir.clone(),
        targets_dir: request.targets_dir.clone(),
        datastore_dir: request.datastore_dir.clone(),
        target_name: target_name.to_string(),
    };
    let target = TufConfigVerifier::verify_local_target(&input)
        .await
        .map_err(|_| {
            ConfigCandidateError::BundleInvalid("package index target could not be verified")
        })?;
    validate_package_index_claims(&target.target_bytes, verified)
}

async fn validate_remote_package_index_target(
    request: &AuthorizedRemoteTufConfigTarget,
    verified: &registry_platform_config::VerifiedConfigTarget,
) -> Result<(), ConfigCandidateError> {
    let Some(target_name) = verified.metadata.package_index_target_name.as_deref() else {
        return validate_no_unbound_package_digest(verified);
    };
    let input = RemoteTufRepositoryInput {
        root_path: request.root_path.clone(),
        metadata_base_url: request.metadata_base_url.clone(),
        targets_base_url: request.targets_base_url.clone(),
        datastore_dir: request.datastore_dir.clone(),
        target_name: target_name.to_string(),
        allow_dev_insecure_fetch_urls: request.allow_dev_insecure_fetch_urls,
    };
    let target = TufConfigVerifier::verify_remote_target(&input)
        .await
        .map_err(|_| {
            ConfigCandidateError::BundleInvalid("package index target could not be verified")
        })?;
    validate_package_index_claims(&target.target_bytes, verified)
}

fn validate_no_unbound_package_digest(
    verified: &registry_platform_config::VerifiedConfigTarget,
) -> Result<(), ConfigCandidateError> {
    if verified.metadata.package_digest.is_some() {
        return Err(ConfigCandidateError::BundleInvalid(
            "package_digest requires package_index_target_name",
        ));
    }
    Ok(())
}

fn validate_package_index_claims(
    target_bytes: &[u8],
    verified: &registry_platform_config::VerifiedConfigTarget,
) -> Result<(), ConfigCandidateError> {
    let expected_package_digest =
        verified
            .metadata
            .package_digest
            .as_deref()
            .ok_or(ConfigCandidateError::BundleInvalid(
                "package index target requires package_digest",
            ))?;
    let index: Value = serde_json::from_slice(target_bytes).map_err(|_| {
        ConfigCandidateError::CandidateInvalid("package index target payload could not be parsed")
    })?;
    if index.get("package_digest").and_then(Value::as_str) != Some(expected_package_digest) {
        return Err(ConfigCandidateError::BundleInvalid(
            "package index digest did not match signed metadata",
        ));
    }
    if let Some(expected_source_digest) = verified.metadata.source_manifest_digest.as_deref() {
        if index.get("source_manifest_digest").and_then(Value::as_str)
            != Some(expected_source_digest)
        {
            return Err(ConfigCandidateError::BundleInvalid(
                "package index source digest did not match signed metadata",
            ));
        }
    }
    Ok(())
}

fn parse_candidate_metadata(
    config: &Config,
    candidate: &ResolvedConfigCandidate,
) -> Result<(Option<CompiledMetadata>, Option<String>), &'static str> {
    match (&config.metadata, candidate.metadata_yaml.as_deref()) {
        (Some(metadata_config), Some(metadata_yaml)) => {
            let manifest: MetadataManifest = serde_saphyr::from_str(metadata_yaml)
                .map_err(|_| "candidate metadata payload could not be parsed")?;
            let digest = metadata_core::source_manifest_digest(&manifest)
                .map_err(|_| "candidate metadata digest could not be computed")?;
            if let Some(expected) = metadata_config.source.digest.as_deref() {
                if expected != digest {
                    return Err("candidate metadata digest did not match runtime config");
                }
            }
            if let Some(expected) = candidate.metadata_source_digest.as_deref() {
                if expected != digest {
                    return Err("candidate metadata digest did not match signed target metadata");
                }
            }
            let compiled = metadata_core::compile_manifest(&manifest)
                .map_err(|_| "candidate metadata payload did not validate")?;
            config::validate::validate_runtime_bindings(config, &compiled)
                .map_err(|_| "candidate metadata did not match runtime bindings")?;
            Ok((Some(compiled), Some(digest)))
        }
        (Some(_), None)
            if is_signed_config_source(candidate.source)
                && (candidate.metadata_source_digest.is_some()
                    || candidate.package_digest.is_some()) =>
        {
            Err("candidate metadata payload is required")
        }
        (Some(_), None) => Ok((None, None)),
        (None, Some(_)) => Err("candidate metadata payload was provided without metadata config"),
        (None, None) => Ok((None, None)),
    }
}

fn validate_metadata_source_digest_claim(
    metadata_yaml: &str,
    expected: Option<&str>,
) -> Result<(), ConfigCandidateError> {
    let Some(expected) = expected else {
        return Err(ConfigCandidateError::BundleInvalid(
            "metadata target requires source_manifest_digest",
        ));
    };
    let manifest: MetadataManifest = serde_saphyr::from_str(metadata_yaml).map_err(|_| {
        ConfigCandidateError::CandidateInvalid("metadata target payload could not be parsed")
    })?;
    let actual = metadata_core::source_manifest_digest(&manifest).map_err(|_| {
        ConfigCandidateError::CandidateInvalid("metadata target digest could not be computed")
    })?;
    if expected != actual {
        return Err(ConfigCandidateError::BundleInvalid(
            "metadata target digest did not match signed metadata",
        ));
    }
    Ok(())
}

fn runtime_package_digest(
    config_yaml: &str,
    config: &Config,
    metadata_source_digest: Option<&str>,
    package_digest: Option<&str>,
    source: ConfigSource,
) -> Result<String, &'static str> {
    let environment = config
        .instance
        .environment
        .as_deref()
        .unwrap_or("development");
    let mut preimage = serde_json::json!({
        "schema_version": "registry-runtime-package/v1",
        "product": "registry-relay",
        "instance_id": config.instance.id,
        "environment": environment,
        "runtime_config_digest": internal_config_hash(config_yaml.as_bytes()),
        "source": source.as_posture_str(),
    });
    if let Some(digest) = metadata_source_digest {
        preimage["source_manifest_digest"] = Value::String(digest.to_string());
    }
    if let Some(digest) = package_digest {
        preimage["package_digest"] = Value::String(digest.to_string());
    }
    let bytes = metadata_core::canonicalize_json(&preimage)
        .map_err(|_| "runtime package digest could not be computed")?;
    Ok(internal_config_hash(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_remote_tuf_repo() -> Config {
        serde_saphyr::from_str(
            r#"
server:
  bind: 127.0.0.1:0
config_trust:
  antirollback_state_path: /tmp/relay-antirollback.json
  local_approval_state_path: /tmp/relay-local-approvals.json
  remote_tuf_repositories:
    - root_path: /etc/registry-relay/tuf/root.json
      metadata_base_url: https://config.example.test/metadata
      targets_base_url: https://config.example.test/targets
      datastore_dir: /var/lib/registry-relay/tuf
      allow_dev_insecure_fetch_urls: false
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
"#,
        )
        .expect("config parses")
    }

    fn remote_request(metadata_base_url: &str) -> RemoteTufConfigTargetRequest {
        RemoteTufConfigTargetRequest {
            root_path: "/etc/registry-relay/tuf/root.json".into(),
            metadata_base_url: metadata_base_url.to_string(),
            targets_base_url: "https://config.example.test/targets".to_string(),
            datastore_dir: "/var/lib/registry-relay/tuf".into(),
            target_name: "registry-relay.yaml".to_string(),
            allow_dev_insecure_fetch_urls: true,
        }
    }

    #[test]
    fn remote_tuf_request_must_match_configured_repository() {
        let config = config_with_remote_tuf_repo();

        let err = authorize_remote_tuf_config_request(
            &remote_request("https://evil.example/metadata"),
            &config,
        )
        .expect_err("unlisted repository fails closed");

        assert!(matches!(err, ConfigCandidateError::BundleInvalid(_)));
    }

    #[test]
    fn remote_tuf_request_uses_operator_fetch_policy() {
        let config = config_with_remote_tuf_repo();

        let authorized = authorize_remote_tuf_config_request(
            &remote_request("https://config.example.test/metadata"),
            &config,
        )
        .expect("configured repository is authorized");

        assert!(!authorized.allow_dev_insecure_fetch_urls);
        assert_eq!(authorized.target_name, "registry-relay.yaml");
    }
}
