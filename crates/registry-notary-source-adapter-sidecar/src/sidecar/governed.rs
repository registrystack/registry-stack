use super::*;

#[derive(Clone, Debug)]
pub(super) struct GovernedAcceptance {
    antirollback_state_path: PathBuf,
    key: AntiRollbackKey,
    proposal: AntiRollbackProposal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GovernedRuntimeTarget {
    schema: String,
    limits: LimitConfig,
    sources: BTreeMap<String, SourceConfig>,
}

pub async fn load_startup_config(raw: &str) -> Result<SidecarConfig, SidecarError> {
    load_startup_config_with_options(raw, false).await
}

pub async fn load_startup_config_with_options(
    raw: &str,
    _allow_unsigned_dev_config: bool,
) -> Result<SidecarConfig, SidecarError> {
    let probe: SidecarConfigTrustProbe =
        serde_norway::from_str(raw).map_err(|error| SidecarError::Config(error.to_string()))?;
    if probe.config_trust.is_none() {
        return serde_norway::from_str(raw)
            .map_err(|error| SidecarError::Config(error.to_string()));
    }
    Err(SidecarError::Config(
        "sidecar config_trust TUF startup is no longer supported; use a local sidecar manifest"
            .to_string(),
    ))
}

#[derive(Debug, Deserialize)]
struct SidecarConfigTrustProbe {
    #[serde(default)]
    config_trust: Option<Value>,
}

pub fn render_governed_runtime_target_json(raw_manifest: &str) -> Result<Vec<u8>, SidecarError> {
    let config: SidecarConfig = serde_norway::from_str(raw_manifest)
        .map_err(|error| SidecarError::Config(error.to_string()))?;
    let target = GovernedRuntimeTarget {
        schema: "registry.notary.source_adapter_sidecar.runtime.v1".to_string(),
        limits: config.limits,
        sources: config.sources,
    };
    validate_governed_runtime_target(&target)?;
    let mut bytes = serde_json::to_vec_pretty(&target).map_err(|error| {
        SidecarError::Config(format!("target JSON could not be rendered: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn verify_governed_bundle_report_json(target_bytes: &[u8]) -> Result<Value, SidecarError> {
    let target = governed_target_from_bytes(target_bytes)?;
    validate_governed_runtime_target(&target)?;
    Ok(json!({
        "verified": true,
        "target_name": "<local-target-json>",
        "config_hash": registry_platform_config::sha256_uri(target_bytes),
    }))
}

fn governed_target_from_bytes(target_bytes: &[u8]) -> Result<GovernedRuntimeTarget, SidecarError> {
    serde_json::from_slice(target_bytes).map_err(|error| {
        SidecarError::StartupCheck(format!("governed runtime target is invalid JSON: {error}"))
    })
}

fn validate_governed_runtime_target(target: &GovernedRuntimeTarget) -> Result<(), SidecarError> {
    if target.schema != "registry.notary.source_adapter_sidecar.runtime.v1" {
        return Err(SidecarError::StartupCheck(
            "governed runtime target schema is unsupported".to_string(),
        ));
    }
    let config = SidecarConfig {
        server: ServerConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            request_timeout_ms: default_request_timeout_ms(),
            request_body_timeout_ms: default_request_body_timeout_ms(),
            http1_header_read_timeout_ms: default_http1_header_read_timeout_ms(),
            max_connections: default_max_connections(),
            metrics_require_auth: false,
        },
        auth: AuthConfig {
            bearer_tokens: vec![BearerTokenConfig {
                id: "release-helper".to_string(),
                token: None,
                hash_env: Some(
                    "REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_RELEASE_HELPER_TOKEN_HASH".to_string(),
                ),
            }],
        },
        audit: SidecarAuditConfig::default(),
        config_trust: None,
        limits: target.limits.clone(),
        sources: target.sources.clone(),
        assurance: None,
        governed_acceptance: None,
    };
    validate_config(&config)
}

pub(super) fn accept_governed_config(config: &SidecarConfig) -> Result<(), SidecarError> {
    let Some(governed) = &config.governed_acceptance else {
        return Ok(());
    };
    FileAntiRollbackStore::new(&governed.antirollback_state_path)
        .accept(&governed.key, governed.proposal.clone())
        .map_err(|error| {
            SidecarError::StartupCheck(format!("anti-rollback acceptance failed: {error}"))
        })?;
    Ok(())
}
