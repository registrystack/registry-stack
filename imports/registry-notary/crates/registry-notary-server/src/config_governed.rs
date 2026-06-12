// SPDX-License-Identifier: Apache-2.0
//! Governed configuration bundle verification shared by admin and CLI paths.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

use registry_notary_core::{
    deprecated_config_fields, ConfigTrustConfig, RemoteTufRepositoryConfig,
    StandaloneRegistryNotaryConfig,
};
use registry_platform_config::{
    reject_deprecated_config_fields, LocalTufRepositoryInput, RemoteTufRepositoryInput,
    TufConfigVerifier, VerificationContext,
};
use registry_platform_ops::{internal_config_hash, is_sha256_config_hash, ConfigSource};
use serde::Deserialize;
use serde_json::Value;

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

#[derive(Debug, Clone)]
struct AuthorizedRemoteTufConfigTarget {
    root_path: PathBuf,
    metadata_base_url: String,
    targets_base_url: String,
    datastore_dir: PathBuf,
    target_name: String,
    allow_dev_insecure_fetch_urls: bool,
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

pub struct ResolvedConfigCandidate {
    pub bundle_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub previous_config_hash: Option<String>,
    pub previous_config_hash_format: Option<PreviousConfigHashFormat>,
    pub root_version: Option<u64>,
    pub change_classes: BTreeSet<String>,
    pub signer_kids: BTreeSet<String>,
    pub tuf_root_sha256: Option<String>,
    pub config_yaml: String,
    pub(crate) source: ConfigSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviousConfigHashFormat {
    Sha256Prefixed,
    BareLowercaseHex,
}

impl PreviousConfigHashFormat {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256Prefixed => "sha256-prefixed",
            Self::BareLowercaseHex => "bare lowercase hex",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NormalizedPreviousConfigHash {
    pub value: Option<String>,
    pub format: Option<PreviousConfigHashFormat>,
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

pub fn normalize_previous_config_hash(
    value: Option<&str>,
) -> Result<NormalizedPreviousConfigHash, ConfigCandidateError> {
    let Some(value) = value else {
        return Ok(NormalizedPreviousConfigHash::default());
    };
    if is_sha256_config_hash(value) {
        return Ok(NormalizedPreviousConfigHash {
            value: Some(value.to_string()),
            format: Some(PreviousConfigHashFormat::Sha256Prefixed),
        });
    }
    if is_lowercase_sha256_hex(value) {
        return Ok(NormalizedPreviousConfigHash {
            value: Some(format!("sha256:{value}")),
            format: Some(PreviousConfigHashFormat::BareLowercaseHex),
        });
    }
    Err(ConfigCandidateError::CandidateInvalid(
        "previous_config_hash must be sha256:<64 lowercase hex> or bare <64 lowercase hex>",
    ))
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
            let authorized =
                authorize_remote_tuf_config_request(request, governance.config_trust())?;
            let input = RemoteTufRepositoryInput {
                root_path: authorized.root_path.clone(),
                metadata_base_url: authorized.metadata_base_url.clone(),
                targets_base_url: authorized.targets_base_url.clone(),
                datastore_dir: authorized.datastore_dir.clone(),
                target_name: authorized.target_name.clone(),
                allow_dev_insecure_fetch_urls: authorized.allow_dev_insecure_fetch_urls,
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
    let previous_config_hash =
        normalize_previous_config_hash(verified.metadata.previous_config_hash.as_deref())?;
    Ok(ResolvedConfigCandidate {
        bundle_id: verified.metadata.bundle_id,
        stream_id: verified.metadata.stream_id,
        sequence: verified.metadata.sequence,
        previous_config_hash: previous_config_hash.value,
        previous_config_hash_format: previous_config_hash.format,
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

fn authorize_remote_tuf_config_request(
    request: &RemoteTufConfigTargetRequest,
    config_trust: Option<&ConfigTrustConfig>,
) -> Result<AuthorizedRemoteTufConfigTarget, ConfigCandidateError> {
    let Some(config_trust) = config_trust else {
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

pub fn parse_candidate_config(config_yaml: &str) -> Result<StandaloneRegistryNotaryConfig, String> {
    let value: Value = serde_norway::from_str(config_yaml)
        .map_err(|error| format!("candidate config could not be parsed: {error}"))?;
    reject_deprecated_config_fields(&value, &deprecated_config_fields())
        .map_err(|error| error.to_string())?;
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(config_yaml)
        .map_err(|error| format!("candidate config could not be parsed: {error}"))?;
    config
        .validate()
        .map_err(|error| format!("candidate config did not validate: {error}"))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use registry_notary_core::{
        ConfigTrustConfig, ConfigTrustRateLimit, RemoteTufRepositoryConfig,
    };

    use super::*;

    #[test]
    fn parse_candidate_config_names_deprecated_field_replacements() {
        let err = parse_candidate_config("audit:\n  max_size_bytes: 10485760\n")
            .expect_err("deprecated candidate field is rejected");

        assert!(err.contains("audit.max_size_mb"), "unexpected: {err}");
    }

    fn config_trust_with_remote_repo() -> ConfigTrustConfig {
        ConfigTrustConfig {
            antirollback_state_path: "/var/lib/registry-notary/config-antirollback.json".into(),
            local_approval_state_path: "/var/lib/registry-notary/config-local-approvals.json"
                .into(),
            break_glass_rate_limit: ConfigTrustRateLimit {
                max_accepted: 1,
                window_seconds: 3600,
            },
            accepted_roots: Vec::new(),
            remote_tuf_repositories: vec![RemoteTufRepositoryConfig {
                root_path: "/etc/registry-notary/tuf/root.json".into(),
                metadata_base_url: "https://config.example.test/metadata".to_string(),
                targets_base_url: "https://config.example.test/targets".to_string(),
                datastore_dir: "/var/lib/registry-notary/tuf".into(),
                allow_dev_insecure_fetch_urls: false,
            }],
        }
    }

    fn remote_request(metadata_base_url: &str) -> RemoteTufConfigTargetRequest {
        RemoteTufConfigTargetRequest {
            root_path: "/etc/registry-notary/tuf/root.json".into(),
            metadata_base_url: metadata_base_url.to_string(),
            targets_base_url: "https://config.example.test/targets".to_string(),
            datastore_dir: "/var/lib/registry-notary/tuf".into(),
            target_name: "registry-notary.yaml".to_string(),
            allow_dev_insecure_fetch_urls: true,
        }
    }

    #[test]
    fn remote_tuf_request_without_configured_repositories_is_rejected() {
        let config_trust = ConfigTrustConfig {
            antirollback_state_path: "/var/lib/registry-notary/config-antirollback.json".into(),
            local_approval_state_path: "/var/lib/registry-notary/config-local-approvals.json"
                .into(),
            break_glass_rate_limit: ConfigTrustRateLimit {
                max_accepted: 1,
                window_seconds: 3600,
            },
            accepted_roots: Vec::new(),
            remote_tuf_repositories: Vec::new(),
        };

        let err = authorize_remote_tuf_config_request(
            &remote_request("https://config.example.test/metadata"),
            Some(&config_trust),
        )
        .expect_err("empty allowlist fails closed");

        assert!(matches!(err, ConfigCandidateError::BundleInvalid(_)));
    }

    #[test]
    fn remote_tuf_request_without_config_trust_is_rejected() {
        let err = authorize_remote_tuf_config_request(
            &remote_request("https://config.example.test/metadata"),
            None,
        )
        .expect_err("missing config_trust fails closed");

        assert!(matches!(err, ConfigCandidateError::BundleInvalid(_)));
    }

    #[test]
    fn remote_tuf_request_must_match_configured_repository() {
        let config_trust = config_trust_with_remote_repo();

        let err = authorize_remote_tuf_config_request(
            &remote_request("https://evil.example/metadata"),
            Some(&config_trust),
        )
        .expect_err("unlisted repository fails closed");

        assert!(matches!(err, ConfigCandidateError::BundleInvalid(_)));
        assert!(
            err.detail().contains("not authorized"),
            "error detail: {}",
            err.detail()
        );
    }

    #[test]
    fn remote_tuf_request_uses_operator_fetch_policy() {
        let config_trust = config_trust_with_remote_repo();

        let authorized = authorize_remote_tuf_config_request(
            &remote_request("https://config.example.test/metadata"),
            Some(&config_trust),
        )
        .expect("configured repository is authorized");

        // Operator configured allow_dev_insecure_fetch_urls: false; the request
        // set it to true. Operator's value must win.
        assert!(!authorized.allow_dev_insecure_fetch_urls);
        assert_eq!(authorized.target_name, "registry-notary.yaml");
    }

    #[test]
    fn remote_tuf_source_matches_requires_all_four_fields() {
        let allowed = RemoteTufRepositoryConfig {
            root_path: PathBuf::from("/etc/registry-notary/tuf/root.json"),
            metadata_base_url: "https://config.example.test/metadata".to_string(),
            targets_base_url: "https://config.example.test/targets".to_string(),
            datastore_dir: PathBuf::from("/var/lib/registry-notary/tuf"),
            allow_dev_insecure_fetch_urls: false,
        };

        // Exact match.
        assert!(remote_tuf_source_matches(
            &allowed,
            &remote_request("https://config.example.test/metadata")
        ));

        // Wrong metadata_base_url.
        assert!(!remote_tuf_source_matches(
            &allowed,
            &RemoteTufConfigTargetRequest {
                metadata_base_url: "https://other.example.test/metadata".to_string(),
                ..remote_request("https://config.example.test/metadata")
            }
        ));

        // Wrong targets_base_url.
        assert!(!remote_tuf_source_matches(
            &allowed,
            &RemoteTufConfigTargetRequest {
                targets_base_url: "https://other.example.test/targets".to_string(),
                ..remote_request("https://config.example.test/metadata")
            }
        ));

        // Wrong root_path.
        assert!(!remote_tuf_source_matches(
            &allowed,
            &RemoteTufConfigTargetRequest {
                root_path: PathBuf::from("/etc/other/root.json"),
                ..remote_request("https://config.example.test/metadata")
            }
        ));

        // Wrong datastore_dir.
        assert!(!remote_tuf_source_matches(
            &allowed,
            &RemoteTufConfigTargetRequest {
                datastore_dir: PathBuf::from("/var/lib/other/tuf"),
                ..remote_request("https://config.example.test/metadata")
            }
        ));
    }
}
