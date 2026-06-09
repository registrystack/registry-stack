use crate::{WorkerCommand, WorkerError, WorkerPool, WorkerPoolConfig};
use axum::{
    body::{to_bytes, Body},
    extract::{Path, Query, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{TimeDelta, Utc};
use registry_platform_authcommon::{parse_bearer_token, parse_fingerprint, verify_api_key};
use registry_platform_config::{
    ConfigTargetMetadata, LocalTufRepositoryInput, RegistryAcceptedTrustRoots, RegistryTrustRoot,
    TufConfigVerifier, TufVerifiedTarget, VerificationContext,
};
use registry_platform_ops::{AntiRollbackKey, AntiRollbackProposal, FileAntiRollbackStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    fmt,
    net::SocketAddr,
    num::NonZeroU64,
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::process::Command;
use tokio::sync::Mutex;
use tough::{
    editor::{signed::PathExists, RepositoryEditor},
    key_source::{KeySource, LocalKeySource},
    schema::Target,
};
use tracing::{info, warn};

#[derive(Clone, Debug, Deserialize)]
pub struct SidecarConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub config_trust: Option<SidecarConfigTrustConfig>,
    #[serde(default)]
    pub jobs_root: Option<PathBuf>,
    pub limits: LimitConfig,
    pub openfn: OpenFnConfig,
    pub worker: WorkerProcessConfig,
    pub sources: BTreeMap<String, SourceConfig>,
    #[serde(skip)]
    pub assurance: Option<SidecarAssurance>,
    #[serde(skip)]
    governed_acceptance: Option<GovernedAcceptance>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    pub bearer_tokens: Vec<BearerTokenConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfigTrustConfig {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub root_path: PathBuf,
    pub metadata_dir: PathBuf,
    pub targets_dir: PathBuf,
    pub datastore_dir: PathBuf,
    pub target_name: String,
    pub antirollback_state_path: PathBuf,
    #[serde(default)]
    pub accepted_roots: Vec<RegistryTrustRoot>,
}

#[derive(Clone, Deserialize)]
pub struct BearerTokenConfig {
    pub id: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub hash_env: Option<String>,
}

impl fmt::Debug for BearerTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerTokenConfig")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .field("hash_env", &self.hash_env)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LimitConfig {
    pub max_workers: usize,
    pub worker_timeout_ms: u64,
    pub max_output_bytes: usize,
    pub max_request_bytes: usize,
    pub max_query_parameter_bytes: usize,
    #[serde(default = "default_liveness_window_ms")]
    pub liveness_window_ms: u64,
    #[serde(default = "default_retry_after_seconds")]
    pub retry_after_seconds: u64,
    #[serde(default = "default_max_batch_items")]
    pub max_batch_items: usize,
    pub max_worker_memory_mb: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenFnConfig {
    pub cli_build_tool: String,
    pub runtime: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerProcessConfig {
    pub command: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub version_args: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceConfig {
    pub dataset: String,
    pub entity: String,
    pub workflow: SourceWorkflowConfig,
    pub credential_env: String,
    #[serde(default)]
    pub allowed_base_urls: Vec<String>,
    #[serde(default)]
    pub smoke_lookup: Option<SmokeLookupConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceWorkflowConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    pub steps: Vec<SourceWorkflowStepConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceWorkflowStepConfig {
    pub id: String,
    pub expression: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression_sha256: Option<String>,
    pub adaptors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<SourceWorkflowNextConfig>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SidecarAssurance {
    pub status: String,
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub bundle_id: String,
    pub sequence: u64,
    pub config_hash: String,
    pub tuf_root_sha256: String,
    pub root_version: u64,
    pub targets_version: u64,
    pub snapshot_version: u64,
    pub timestamp_version: u64,
    pub change_classes: BTreeSet<String>,
    pub signer_kids: Vec<String>,
    pub expression_hashes_verified: bool,
    pub runtime_verified: bool,
    pub smoke_verified: bool,
    pub apply_policy: String,
}

#[derive(Clone, Debug)]
struct GovernedAcceptance {
    antirollback_state_path: PathBuf,
    key: AntiRollbackKey,
    proposal: AntiRollbackProposal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GovernedRuntimeTarget {
    schema: String,
    limits: LimitConfig,
    openfn: OpenFnConfig,
    jobs_root: PathBuf,
    worker: WorkerProcessConfig,
    sources: BTreeMap<String, SourceConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SourceWorkflowNextConfig {
    Step(String),
    Edges(BTreeMap<String, SourceWorkflowEdgeConfig>),
}

impl SourceWorkflowNextConfig {
    fn target_ids(&self) -> Vec<&str> {
        match self {
            Self::Step(step) => vec![step.as_str()],
            Self::Edges(edges) => edges.keys().map(String::as_str).collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SourceWorkflowEdgeConfig {
    Enabled(bool),
    Condition(String),
    Edge(SourceWorkflowEdgeObjectConfig),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceWorkflowEdgeObjectConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmokeLookupConfig {
    pub field: String,
    pub value: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default = "default_smoke_purpose")]
    pub purpose: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchMatchRequest {
    fields: Vec<String>,
    query_signature: Vec<BatchQueryTerm>,
    items: Vec<BatchMatchItem>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchQueryTerm {
    field: String,
    op: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchMatchItem {
    id: String,
    values: Vec<Value>,
}

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("sidecar config error: {0}")]
    Config(String),
    #[error("worker pool error: {0}")]
    Worker(#[from] WorkerError),
    #[error("failed to bind or serve sidecar: {0}")]
    Io(#[from] std::io::Error),
    #[error("credential env {env} for source {source_id} is missing")]
    MissingCredential { source_id: String, env: String },
    #[error("credential env {env} for source {source_id} is not valid JSON: {source}")]
    CredentialJson {
        source_id: String,
        env: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("credential env {env} for source {source_id} has disallowed or missing baseUrl")]
    CredentialBaseUrl { source_id: String, env: String },
    #[error("auth token hash env {env} for bearer token {token_id} is missing")]
    MissingTokenHashEnv { token_id: String, env: String },
    #[error("auth token hash env {env} for bearer token {token_id} is invalid")]
    InvalidTokenHashEnv { token_id: String, env: String },
    #[error("startup check failed: {0}")]
    StartupCheck(String),
    #[error("smoke lookup for source {source_id} failed: {reason}")]
    SmokeLookup { source_id: String, reason: String },
}

#[derive(Clone)]
struct AppState {
    config: SidecarConfig,
    auth_tokens: Arc<Vec<ResolvedBearerToken>>,
    pool: Arc<WorkerPool>,
    credentials: Arc<BTreeMap<String, Value>>,
    metrics: Arc<Mutex<BTreeMap<MetricKey, MetricValue>>>,
}

#[derive(Clone)]
struct ResolvedBearerToken {
    fingerprint: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MetricKey {
    source_id: String,
    outcome: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct MetricValue {
    count: u64,
    duration_ms_total: u64,
}

pub async fn load_startup_config(raw: &str) -> Result<SidecarConfig, SidecarError> {
    load_startup_config_with_options(raw, false).await
}

pub async fn load_startup_config_with_options(
    raw: &str,
    allow_unsigned_dev_config: bool,
) -> Result<SidecarConfig, SidecarError> {
    let probe: SidecarConfigTrustProbe =
        serde_norway::from_str(raw).map_err(|error| SidecarError::Config(error.to_string()))?;
    if probe.config_trust.is_none() {
        if allow_unsigned_dev_config {
            return serde_norway::from_str(raw)
                .map_err(|error| SidecarError::Config(error.to_string()));
        }
        return Err(SidecarError::Config(
            "config_trust is required; use --allow-unsigned-dev-config only for local unsigned development manifests".to_string(),
        ));
    }
    let bootstrap: SidecarBootstrapConfig =
        serde_norway::from_str(raw).map_err(|error| SidecarError::Config(error.to_string()))?;
    load_governed_startup_config(bootstrap).await
}

#[derive(Debug, Deserialize)]
struct SidecarConfigTrustProbe {
    #[serde(default)]
    config_trust: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarBootstrapConfig {
    server: ServerConfig,
    auth: AuthConfig,
    config_trust: SidecarConfigTrustConfig,
}

#[derive(Clone, Debug)]
pub struct LocalTufBundleVerifyOptions {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub root_path: PathBuf,
    pub metadata_dir: PathBuf,
    pub targets_dir: PathBuf,
    pub datastore_dir: PathBuf,
    pub target_name: String,
}

#[derive(Clone, Debug)]
pub struct CreateLocalTufRepoOptions {
    pub target_path: PathBuf,
    pub target_name: String,
    pub root_path: PathBuf,
    pub signing_key_path: PathBuf,
    pub metadata_dir: PathBuf,
    pub targets_dir: PathBuf,
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub bundle_id: String,
    pub sequence: u64,
    pub previous_config_hash: String,
    pub change_classes: Vec<String>,
    pub declared_signer_kids: Vec<String>,
    pub apply_policy: String,
    pub targets_expiration_days: i64,
    pub snapshot_expiration_days: i64,
    pub timestamp_expiration_days: i64,
}

pub fn render_governed_runtime_target_json(
    raw_manifest: &str,
    jobs_root: &FsPath,
) -> Result<Vec<u8>, SidecarError> {
    let config: SidecarConfig = serde_norway::from_str(raw_manifest)
        .map_err(|error| SidecarError::Config(error.to_string()))?;
    let canonical_jobs_root = canonical_jobs_root(jobs_root)?;
    let mut target = GovernedRuntimeTarget {
        schema: "registry.notary.openfn_sidecar.runtime.v1".to_string(),
        limits: config.limits,
        openfn: config.openfn,
        jobs_root: jobs_root.to_path_buf(),
        worker: config.worker,
        sources: config.sources,
    };
    populate_expression_hashes(&mut target, &canonical_jobs_root)?;
    validate_governed_runtime_target(&target)?;
    let mut bytes = serde_json::to_vec_pretty(&target).map_err(|error| {
        SidecarError::Config(format!("target JSON could not be rendered: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn print_expression_hashes_report_json(target_bytes: &[u8]) -> Result<Value, SidecarError> {
    let target = governed_target_from_bytes(target_bytes)?;
    validate_governed_runtime_target(&target)?;
    let expression_hashes = expression_hashes_for_target(&target)?;
    Ok(json!({
        "config_hash": registry_platform_config::sha256_uri(target_bytes),
        "jobs_root": target.jobs_root,
        "expression_hashes": expression_hashes,
    }))
}

pub async fn create_local_tuf_demo_repo_report_json(
    options: CreateLocalTufRepoOptions,
) -> Result<Value, SidecarError> {
    validate_target_name(&options.target_name)?;
    if options.sequence == 0 {
        return Err(SidecarError::Config(
            "TUF metadata sequence must be greater than zero".to_string(),
        ));
    }
    if options.change_classes.is_empty() {
        return Err(SidecarError::Config(
            "at least one change class is required".to_string(),
        ));
    }
    let declared_signer_kids = if options.declared_signer_kids.is_empty() {
        vec!["local-demo-signer".to_string()]
    } else {
        options.declared_signer_kids.clone()
    };
    let target_bytes = std::fs::read(&options.target_path).map_err(|error| {
        SidecarError::Config(format!(
            "target {} could not be read: {error}",
            options.target_path.display()
        ))
    })?;
    let target = governed_target_from_bytes(&target_bytes)?;
    validate_governed_runtime_target(&target)?;
    let expression_hashes = expression_hashes_for_target(&target)?;
    let config_hash = registry_platform_config::sha256_uri(&target_bytes);

    let source_targets_dir = options.metadata_dir.join(".source-targets");
    if source_targets_dir.exists() {
        std::fs::remove_dir_all(&source_targets_dir).map_err(|error| {
            SidecarError::Config(format!(
                "stale TUF source target staging directory {} could not be removed: {error}",
                source_targets_dir.display()
            ))
        })?;
    }
    let staged_target_path = source_targets_dir.join(&options.target_name);
    if let Some(parent) = staged_target_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            SidecarError::Config(format!(
                "TUF source target staging directory {} could not be created: {error}",
                parent.display()
            ))
        })?;
    }
    std::fs::copy(&options.target_path, &staged_target_path).map_err(|error| {
        SidecarError::Config(format!(
            "target could not be staged as {}: {error}",
            staged_target_path.display()
        ))
    })?;

    let mut tuf_target = Target::from_path(&staged_target_path)
        .await
        .map_err(|error| {
            SidecarError::Config(format!("target metadata could not be built: {error}"))
        })?;
    let custom = json!({
        "product": options.product,
        "instance_id": options.instance_id,
        "environment": options.environment,
        "stream_id": options.stream_id,
        "bundle_id": options.bundle_id,
        "sequence": options.sequence,
        "previous_config_hash": options.previous_config_hash,
        "config_hash": config_hash,
        "change_classes": options.change_classes,
        "signer_kids": declared_signer_kids.clone(),
        "apply_policy": options.apply_policy
    });
    let Value::Object(custom) = custom else {
        return Err(SidecarError::Config(
            "custom target metadata was not an object".to_string(),
        ));
    };
    tuf_target.custom = custom.into_iter().collect::<HashMap<_, _>>();

    let version = NonZeroU64::new(options.sequence).ok_or_else(|| {
        SidecarError::Config("TUF metadata sequence must be greater than zero".to_string())
    })?;
    let mut editor = RepositoryEditor::new(&options.root_path)
        .await
        .map_err(|error| SidecarError::Config(format!("TUF root could not be loaded: {error}")))?;
    editor
        .targets_expires(expiry_from_days(options.targets_expiration_days)?)
        .map_err(|error| {
            SidecarError::Config(format!("TUF targets expiration could not be set: {error}"))
        })?;
    editor.targets_version(version).map_err(|error| {
        SidecarError::Config(format!("TUF targets version could not be set: {error}"))
    })?;
    editor.snapshot_expires(expiry_from_days(options.snapshot_expiration_days)?);
    editor.snapshot_version(version);
    editor.timestamp_expires(expiry_from_days(options.timestamp_expiration_days)?);
    editor.timestamp_version(version);
    editor
        .add_target(options.target_name.clone(), tuf_target)
        .map_err(|error| SidecarError::Config(format!("TUF target could not be added: {error}")))?;
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
        path: options.signing_key_path.clone(),
    })];
    let signed = editor.sign(&keys).await.map_err(|error| {
        SidecarError::Config(format!("TUF repository could not be signed: {error}"))
    })?;
    signed.write(&options.metadata_dir).await.map_err(|error| {
        SidecarError::Config(format!("TUF metadata could not be written: {error}"))
    })?;
    signed
        .copy_targets(&source_targets_dir, &options.targets_dir, PathExists::Fail)
        .await
        .map_err(|error| {
            SidecarError::Config(format!("TUF targets could not be written: {error}"))
        })?;
    std::fs::remove_dir_all(&source_targets_dir).map_err(|error| {
        SidecarError::Config(format!(
            "TUF source target staging directory {} could not be removed: {error}",
            source_targets_dir.display()
        ))
    })?;

    Ok(json!({
        "created": true,
        "target_name": options.target_name,
        "config_hash": config_hash,
        "metadata_dir": options.metadata_dir,
        "targets_dir": options.targets_dir,
        "root_path": options.root_path,
        "expression_hashes": expression_hashes,
        "metadata": {
            "product": options.product,
            "instance_id": options.instance_id,
            "environment": options.environment,
            "stream_id": options.stream_id,
            "bundle_id": options.bundle_id,
            "sequence": options.sequence,
            "previous_config_hash": options.previous_config_hash,
            "config_hash": config_hash,
            "change_classes": options.change_classes,
            "signer_kids": declared_signer_kids,
            "apply_policy": options.apply_policy,
        }
    }))
}

pub async fn verify_governed_bundle_report_json(
    target_bytes: Option<&[u8]>,
    local_tuf: Option<LocalTufBundleVerifyOptions>,
) -> Result<Value, SidecarError> {
    let (target_name, target_bytes, tuf_report, metadata_report) = match local_tuf {
        Some(options) => {
            let context = VerificationContext {
                product: options.product,
                instance_id: options.instance_id,
                environment: options.environment,
            };
            let input = LocalTufRepositoryInput {
                root_path: options.root_path,
                metadata_dir: options.metadata_dir,
                targets_dir: options.targets_dir,
                datastore_dir: options.datastore_dir,
                target_name: options.target_name,
            };
            let verified = TufConfigVerifier::verify_config_target(&input, &context)
                .await
                .map_err(|error| {
                    SidecarError::StartupCheck(format!("TUF target verification failed: {error}"))
                })?;
            if verified.metadata.stream_id != options.stream_id {
                return Err(SidecarError::StartupCheck(
                    "signed config target stream_id does not match expected stream_id".to_string(),
                ));
            }
            let target_name = verified.tuf.target_name.clone();
            let tuf_report = tuf_report(&verified.tuf);
            let metadata_report = metadata_report(&verified.metadata);
            (
                target_name,
                verified.tuf.target_bytes,
                Some(tuf_report),
                Some(metadata_report),
            )
        }
        None => {
            let bytes = target_bytes
                .ok_or_else(|| {
                    SidecarError::Config(
                        "target bytes are required when local TUF options are absent".to_string(),
                    )
                })?
                .to_vec();
            ("<local-target-json>".to_string(), bytes, None, None)
        }
    };
    let target = governed_target_from_bytes(&target_bytes)?;
    validate_governed_runtime_target(&target)?;
    let expression_hashes = expression_hashes_for_target(&target)?;
    Ok(json!({
        "verified": true,
        "target_name": target_name,
        "config_hash": registry_platform_config::sha256_uri(&target_bytes),
        "jobs_root": target.jobs_root,
        "expression_hashes": expression_hashes,
        "tuf": tuf_report,
        "metadata": metadata_report,
    }))
}

fn validate_target_name(target_name: &str) -> Result<(), SidecarError> {
    if target_name.trim().is_empty() {
        return Err(SidecarError::Config(
            "TUF target name must not be blank".to_string(),
        ));
    }
    let path = FsPath::new(target_name);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        return Err(SidecarError::Config(
            "TUF target name must be a relative path without traversal".to_string(),
        ));
    }
    Ok(())
}

fn expiry_from_days(days: i64) -> Result<chrono::DateTime<Utc>, SidecarError> {
    let duration = TimeDelta::try_days(days).ok_or_else(|| {
        SidecarError::Config("TUF expiration days are outside the supported range".to_string())
    })?;
    Utc::now().checked_add_signed(duration).ok_or_else(|| {
        SidecarError::Config("TUF expiration is outside the supported range".to_string())
    })
}

async fn load_governed_startup_config(
    bootstrap: SidecarBootstrapConfig,
) -> Result<SidecarConfig, SidecarError> {
    validate_config_trust(&bootstrap.config_trust)?;
    let context = VerificationContext {
        product: bootstrap.config_trust.product.clone(),
        instance_id: bootstrap.config_trust.instance_id.clone(),
        environment: bootstrap.config_trust.environment.clone(),
    };
    let input = LocalTufRepositoryInput {
        root_path: bootstrap.config_trust.root_path.clone(),
        metadata_dir: bootstrap.config_trust.metadata_dir.clone(),
        targets_dir: bootstrap.config_trust.targets_dir.clone(),
        datastore_dir: bootstrap.config_trust.datastore_dir.clone(),
        target_name: bootstrap.config_trust.target_name.clone(),
    };
    let verified = TufConfigVerifier::verify_config_target(&input, &context)
        .await
        .map_err(|error| {
            SidecarError::StartupCheck(format!("TUF target verification failed: {error}"))
        })?;
    if verified.metadata.stream_id != bootstrap.config_trust.stream_id {
        return Err(SidecarError::StartupCheck(
            "signed config target stream_id does not match bootstrap config_trust".to_string(),
        ));
    }
    if verified.metadata.apply_policy != "restart_required" {
        return Err(SidecarError::StartupCheck(
            "signed config target apply_policy must be restart_required".to_string(),
        ));
    }
    let accepted_roots = RegistryAcceptedTrustRoots {
        accepted_roots: bootstrap.config_trust.accepted_roots.clone(),
    };
    accepted_roots
        .authorize(
            &verified.metadata.change_classes,
            &verified.tuf.signer_kids,
            &verified.tuf.root_sha256,
        )
        .map_err(|error| {
            SidecarError::StartupCheck(format!(
                "signed config target was not authorized by local trust roots: {error}"
            ))
        })?;
    let target: GovernedRuntimeTarget = serde_json::from_slice(&verified.tuf.target_bytes)
        .map_err(|error| {
            SidecarError::StartupCheck(format!("governed runtime target is invalid JSON: {error}"))
        })?;
    materialize_governed_config(bootstrap, verified.tuf, verified.metadata, target)
}

fn validate_config_trust(config_trust: &SidecarConfigTrustConfig) -> Result<(), SidecarError> {
    for (field, value) in [
        ("product", config_trust.product.as_str()),
        ("instance_id", config_trust.instance_id.as_str()),
        ("environment", config_trust.environment.as_str()),
        ("stream_id", config_trust.stream_id.as_str()),
        ("target_name", config_trust.target_name.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(SidecarError::Config(format!(
                "config_trust.{field} must be non-empty"
            )));
        }
    }
    if config_trust.accepted_roots.is_empty() {
        return Err(SidecarError::Config(
            "config_trust.accepted_roots must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn materialize_governed_config(
    bootstrap: SidecarBootstrapConfig,
    tuf: TufVerifiedTarget,
    metadata: ConfigTargetMetadata,
    target: GovernedRuntimeTarget,
) -> Result<SidecarConfig, SidecarError> {
    if target.schema != "registry.notary.openfn_sidecar.runtime.v1" {
        return Err(SidecarError::StartupCheck(
            "governed runtime target schema is unsupported".to_string(),
        ));
    }
    let key = AntiRollbackKey {
        product: metadata.product.clone(),
        instance_id: metadata.instance_id.clone(),
        environment: metadata.environment.clone(),
        stream_id: metadata.stream_id.clone(),
    };
    let proposal = AntiRollbackProposal {
        sequence: metadata.sequence,
        previous_config_hash: metadata.previous_config_hash.clone(),
        config_hash: metadata.config_hash.clone(),
        root_version: Some(tuf.root_version),
        break_glass: None,
        break_glass_rate_limit: None,
        local_approval: None,
        local_approval_rate_limit: None,
    };
    let assurance = SidecarAssurance {
        status: "ready".to_string(),
        product: metadata.product.clone(),
        instance_id: metadata.instance_id.clone(),
        environment: metadata.environment.clone(),
        stream_id: metadata.stream_id.clone(),
        bundle_id: metadata.bundle_id.clone(),
        sequence: metadata.sequence,
        config_hash: metadata.config_hash.clone(),
        tuf_root_sha256: tuf.root_sha256.clone(),
        root_version: tuf.root_version,
        targets_version: tuf.targets_version,
        snapshot_version: tuf.snapshot_version,
        timestamp_version: tuf.timestamp_version,
        change_classes: metadata.change_classes.clone(),
        signer_kids: tuf.signer_kids.clone(),
        expression_hashes_verified: true,
        runtime_verified: true,
        smoke_verified: true,
        apply_policy: metadata.apply_policy.clone(),
    };
    Ok(SidecarConfig {
        server: bootstrap.server,
        auth: bootstrap.auth,
        config_trust: Some(bootstrap.config_trust.clone()),
        jobs_root: Some(target.jobs_root),
        limits: target.limits,
        openfn: target.openfn,
        worker: target.worker,
        sources: target.sources,
        assurance: Some(assurance),
        governed_acceptance: Some(GovernedAcceptance {
            antirollback_state_path: bootstrap.config_trust.antirollback_state_path,
            key,
            proposal,
        }),
    })
}

fn governed_target_from_bytes(target_bytes: &[u8]) -> Result<GovernedRuntimeTarget, SidecarError> {
    serde_json::from_slice(target_bytes).map_err(|error| {
        SidecarError::StartupCheck(format!("governed runtime target is invalid JSON: {error}"))
    })
}

fn validate_governed_runtime_target(target: &GovernedRuntimeTarget) -> Result<(), SidecarError> {
    if target.schema != "registry.notary.openfn_sidecar.runtime.v1" {
        return Err(SidecarError::StartupCheck(
            "governed runtime target schema is unsupported".to_string(),
        ));
    }
    let config = SidecarConfig {
        server: ServerConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        },
        auth: AuthConfig {
            bearer_tokens: vec![BearerTokenConfig {
                id: "release-helper".to_string(),
                token: None,
                hash_env: Some(
                    "REGISTRY_NOTARY_OPENFN_SIDECAR_RELEASE_HELPER_TOKEN_HASH".to_string(),
                ),
            }],
        },
        config_trust: None,
        jobs_root: Some(target.jobs_root.clone()),
        limits: target.limits.clone(),
        openfn: target.openfn.clone(),
        worker: target.worker.clone(),
        sources: target.sources.clone(),
        assurance: None,
        governed_acceptance: None,
    };
    validate_config(&config)
}

fn populate_expression_hashes(
    target: &mut GovernedRuntimeTarget,
    canonical_jobs_root: &FsPath,
) -> Result<(), SidecarError> {
    for (source_id, source) in &mut target.sources {
        for step in &mut source.workflow.steps {
            let (relative_expression, expression_hash) = resolve_render_expression(
                source_id,
                &format!("workflow step {} expression", step.id),
                canonical_jobs_root,
                &step.expression,
            )?;
            step.expression = relative_expression;
            step.expression_sha256 = Some(expression_hash);
        }
    }
    Ok(())
}

fn expression_hashes_for_target(
    target: &GovernedRuntimeTarget,
) -> Result<BTreeMap<String, String>, SidecarError> {
    let canonical_jobs_root = canonical_jobs_root(&target.jobs_root)?;
    let mut expression_hashes = BTreeMap::new();
    for (source_id, source) in &target.sources {
        for step in &source.workflow.steps {
            let expression_path = resolve_jobs_root_expression(
                source_id,
                &format!("workflow step {} expression", step.id),
                &canonical_jobs_root,
                &step.expression,
            )?;
            let bytes = std::fs::read(&expression_path).map_err(|error| {
                SidecarError::Config(format!(
                    "source {source_id} workflow step {} expression {} could not be read: {error}",
                    step.id,
                    expression_path.display()
                ))
            })?;
            expression_hashes.insert(
                format!("{source_id}.{}", step.id),
                registry_platform_config::sha256_uri(&bytes),
            );
        }
    }
    Ok(expression_hashes)
}

fn resolve_render_expression(
    source_id: &str,
    label: &str,
    jobs_root: &FsPath,
    expression: &FsPath,
) -> Result<(PathBuf, String), SidecarError> {
    let canonical_expression = if expression.is_absolute() {
        expression.canonicalize().map_err(|error| {
            SidecarError::Config(format!(
                "source {source_id} {label} {} could not be canonicalized: {error}",
                expression.display()
            ))
        })?
    } else {
        resolve_jobs_root_expression(source_id, label, jobs_root, expression)?
    };
    if !canonical_expression.starts_with(jobs_root) {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must be under jobs_root"
        )));
    }
    let relative_expression = canonical_expression
        .strip_prefix(jobs_root)
        .map_err(|_| {
            SidecarError::Config(format!(
                "source {source_id} {label} could not be made relative to jobs_root"
            ))
        })?
        .to_path_buf();
    let bytes = std::fs::read(&canonical_expression).map_err(|error| {
        SidecarError::Config(format!(
            "source {source_id} {label} {} could not be read: {error}",
            canonical_expression.display()
        ))
    })?;
    Ok((
        relative_expression,
        registry_platform_config::sha256_uri(&bytes),
    ))
}

fn tuf_report(tuf: &TufVerifiedTarget) -> Value {
    json!({
        "root_sha256": tuf.root_sha256,
        "root_version": tuf.root_version,
        "targets_version": tuf.targets_version,
        "snapshot_version": tuf.snapshot_version,
        "timestamp_version": tuf.timestamp_version,
        "signer_kids": tuf.signer_kids,
    })
}

fn metadata_report(metadata: &ConfigTargetMetadata) -> Value {
    json!({
        "product": metadata.product,
        "instance_id": metadata.instance_id,
        "environment": metadata.environment,
        "stream_id": metadata.stream_id,
        "bundle_id": metadata.bundle_id,
        "sequence": metadata.sequence,
        "previous_config_hash": metadata.previous_config_hash,
        "config_hash": metadata.config_hash,
        "change_classes": metadata.change_classes,
        "signer_kids": metadata.signer_kids,
        "apply_policy": metadata.apply_policy,
    })
}

pub async fn sidecar_router(config: SidecarConfig) -> Result<Router, SidecarError> {
    validate_config(&config)?;
    verify_openfn_runtime(&config).await?;
    let auth_tokens = resolve_auth_tokens(&config)?;

    let mut command = WorkerCommand::new(config.worker.command.clone());
    for arg in &config.worker.args {
        command = command.arg(OsString::from(arg));
    }

    let pool = WorkerPool::new(WorkerPoolConfig {
        command,
        forbidden_env_names: sensitive_worker_env_names(&config),
        max_workers: config.limits.max_workers,
        request_timeout: Duration::from_millis(config.limits.worker_timeout_ms),
        max_request_bytes: config.limits.max_request_bytes,
        max_stdout_bytes: config.limits.max_output_bytes,
        max_stderr_bytes: config.limits.max_output_bytes,
        max_memory_bytes: config
            .limits
            .max_worker_memory_mb
            .map(|megabytes| megabytes.saturating_mul(1024 * 1024)),
        replacement_window: Duration::from_secs(60),
        max_replacements_per_window: config.limits.max_workers.saturating_mul(4).max(4),
        circuit_breaker_cooldown: Duration::from_secs(30),
    })
    .await?;

    let credentials = load_credentials(&config)?;
    let state = Arc::new(AppState {
        config,
        auth_tokens: Arc::new(auth_tokens),
        pool: Arc::new(pool),
        credentials: Arc::new(credentials),
        metrics: Arc::new(Mutex::new(BTreeMap::new())),
    });
    run_smoke_lookups(&state).await?;
    accept_governed_config(&state.config)?;

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/v1/assurance", get(assurance))
        .route("/metrics", get(metrics))
        .route(
            "/v1/datasets/{dataset}/entities/{entity}/records",
            get(lookup),
        )
        .route(
            "/v1/datasets/{dataset}/entities/{entity}/records:batchMatch",
            post(batch_match),
        )
        .with_state(state))
}

fn accept_governed_config(config: &SidecarConfig) -> Result<(), SidecarError> {
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

fn sensitive_worker_env_names(config: &SidecarConfig) -> BTreeSet<OsString> {
    config
        .sources
        .values()
        .map(|source| OsString::from(&source.credential_env))
        .chain(
            config
                .auth
                .bearer_tokens
                .iter()
                .filter_map(|token| token.hash_env.as_ref())
                .map(OsString::from),
        )
        .collect()
}

pub async fn run(config: SidecarConfig) -> Result<(), Box<dyn std::error::Error>> {
    let bind = config.server.bind;
    let app = sidecar_router(config).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn validate_config(config: &SidecarConfig) -> Result<(), SidecarError> {
    let canonical_jobs_root = match &config.jobs_root {
        Some(jobs_root) => Some(canonical_jobs_root(jobs_root)?),
        None => None,
    };
    if config.auth.bearer_tokens.is_empty() {
        return Err(SidecarError::Config(
            "at least one sidecar bearer token is required".to_string(),
        ));
    }
    for token in &config.auth.bearer_tokens {
        match (&token.token, &token.hash_env) {
            (None, Some(hash_env)) if !hash_env.trim().is_empty() => {}
            (Some(_), _) => {
                return Err(SidecarError::Config(format!(
                    "bearer token {} must use hash_env; plaintext token is not supported",
                    token.id
                )));
            }
            (None, None) => {
                return Err(SidecarError::Config(format!(
                    "bearer token {} must set hash_env",
                    token.id
                )));
            }
            (None, Some(_)) => {
                return Err(SidecarError::Config(format!(
                    "bearer token {} hash_env must be non-empty",
                    token.id
                )));
            }
        }
    }
    if config.sources.is_empty() {
        return Err(SidecarError::Config(
            "at least one source binding is required".to_string(),
        ));
    }
    if config.limits.max_workers == 0 {
        return Err(SidecarError::Config(
            "limits.max_workers must be greater than zero".to_string(),
        ));
    }
    if config.limits.worker_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "limits.worker_timeout_ms must be greater than zero".to_string(),
        ));
    }
    match config.limits.max_worker_memory_mb {
        Some(0) => {
            return Err(SidecarError::Config(
                "limits.max_worker_memory_mb must be greater than zero".to_string(),
            ));
        }
        Some(_) => {}
        None => {
            return Err(SidecarError::Config(
                "limits.max_worker_memory_mb must be pinned".to_string(),
            ));
        }
    }
    if config.limits.max_output_bytes == 0
        || config.limits.max_request_bytes == 0
        || config.limits.max_query_parameter_bytes == 0
        || config.limits.max_batch_items == 0
    {
        return Err(SidecarError::Config(
            "byte limits must be greater than zero".to_string(),
        ));
    }
    if config.openfn.cli_build_tool.trim().is_empty() || config.openfn.runtime.trim().is_empty() {
        return Err(SidecarError::Config(
            "openfn.cli_build_tool and openfn.runtime must be pinned".to_string(),
        ));
    }
    for (source_id, source) in &config.sources {
        validate_source_execution(source_id, source, canonical_jobs_root.as_deref())?;
        if source
            .allowed_base_urls
            .iter()
            .any(|url| url.trim().is_empty())
        {
            return Err(SidecarError::Config(format!(
                "source {source_id} allowed_base_urls must not contain empty values"
            )));
        }
        let Some(smoke) = &source.smoke_lookup else {
            return Err(SidecarError::Config(format!(
                "source {source_id} smoke_lookup is required for readiness"
            )));
        };
        if !smoke.fields.iter().any(|field| field == &smoke.field) {
            return Err(SidecarError::Config(format!(
                "source {source_id} smoke_lookup.fields must include lookup field {}",
                smoke.field
            )));
        }
    }
    Ok(())
}

fn validate_source_execution(
    source_id: &str,
    source: &SourceConfig,
    canonical_jobs_root: Option<&FsPath>,
) -> Result<(), SidecarError> {
    validate_source_workflow(source_id, &source.workflow, canonical_jobs_root)
}

fn validate_source_workflow(
    source_id: &str,
    workflow: &SourceWorkflowConfig,
    canonical_jobs_root: Option<&FsPath>,
) -> Result<(), SidecarError> {
    if workflow.steps.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} workflow.steps must not be empty"
        )));
    }

    let mut step_ids = BTreeSet::new();
    for step in &workflow.steps {
        if step.id.trim().is_empty() {
            return Err(SidecarError::Config(format!(
                "source {source_id} workflow step id must be non-empty"
            )));
        }
        if !step_ids.insert(step.id.as_str()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} workflow step {} is duplicated",
                step.id
            )));
        }
        validate_source_expression(
            source_id,
            &format!("workflow step {} expression", step.id),
            &step.expression,
            step.expression_sha256.as_deref(),
            canonical_jobs_root,
        )?;
        if step.adaptors.is_empty() {
            return Err(SidecarError::Config(format!(
                "source {source_id} workflow step {} adaptors must not be empty",
                step.id
            )));
        }
        for (index, adaptor) in step.adaptors.iter().enumerate() {
            validate_source_adaptor(
                source_id,
                &format!("workflow step {} adaptors[{index}]", step.id),
                adaptor,
            )?;
        }
    }

    if let Some(start) = &workflow.start {
        if !step_ids.contains(start.as_str()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} workflow start step {start} is not defined"
            )));
        }
    }
    let mut incoming_counts = BTreeMap::<&str, usize>::new();
    let mut next_by_step = BTreeMap::<&str, Vec<&str>>::new();
    for step in &workflow.steps {
        let Some(next) = &step.next else {
            continue;
        };
        let targets = next.target_ids();
        for target in &targets {
            if !step_ids.contains(*target) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} workflow step {} next step {target} is not defined",
                    step.id
                )));
            }
            let count = incoming_counts.entry(*target).or_default();
            *count += 1;
        }
        next_by_step.insert(step.id.as_str(), targets);
    }
    if let Some((step_id, _count)) = incoming_counts.iter().find(|(_step_id, count)| **count > 1) {
        return Err(SidecarError::Config(format!(
            "source {source_id} workflow step {step_id} has multiple input steps; Lightning-style merge runs a target once per incoming path and is not a join, so aggregation must be encoded in an explicit OpenFn step"
        )));
    }
    let mut visited = BTreeSet::new();
    let mut path = BTreeSet::new();
    for start_step in &workflow.steps {
        detect_workflow_cycle(
            source_id,
            &next_by_step,
            start_step.id.as_str(),
            &mut path,
            &mut visited,
        )?;
    }

    Ok(())
}

fn detect_workflow_cycle<'a>(
    source_id: &str,
    next_by_step: &BTreeMap<&'a str, Vec<&'a str>>,
    current: &'a str,
    path: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), SidecarError> {
    if path.contains(current) {
        return Err(SidecarError::Config(format!(
            "source {source_id} workflow contains a cycle at step {current}"
        )));
    }
    if !visited.insert(current) {
        return Ok(());
    }
    path.insert(current);
    if let Some(next_steps) = next_by_step.get(current) {
        for next in next_steps {
            detect_workflow_cycle(source_id, next_by_step, next, path, visited)?;
        }
    }
    path.remove(current);
    Ok(())
}

fn validate_source_expression(
    source_id: &str,
    label: &str,
    expression: &FsPath,
    expression_sha256: Option<&str>,
    canonical_jobs_root: Option<&FsPath>,
) -> Result<(), SidecarError> {
    let resolved_expression = match canonical_jobs_root {
        Some(jobs_root) => {
            let expected_hash = expression_sha256.ok_or_else(|| {
                SidecarError::Config(format!(
                    "source {source_id} {label} expression_sha256 is required"
                ))
            })?;
            validate_sha256_uri(expected_hash).map_err(|reason| {
                SidecarError::Config(format!(
                    "source {source_id} {label} expression_sha256 is invalid: {reason}"
                ))
            })?;
            resolve_jobs_root_expression(source_id, label, jobs_root, expression)?
        }
        None => expression.to_path_buf(),
    };
    if !resolved_expression.is_file() {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} {} is missing",
            resolved_expression.display()
        )));
    }
    if let (Some(expected_hash), Some(_jobs_root)) = (expression_sha256, canonical_jobs_root) {
        let bytes = std::fs::read(&resolved_expression).map_err(|error| {
            SidecarError::Config(format!(
                "source {source_id} {label} {} could not be read: {error}",
                resolved_expression.display()
            ))
        })?;
        let actual_hash = registry_platform_config::sha256_uri(&bytes);
        if actual_hash != expected_hash {
            return Err(SidecarError::Config(format!(
                "source {source_id} {label} hash mismatch: expected {expected_hash}, got {actual_hash}"
            )));
        }
    }
    Ok(())
}

fn canonical_jobs_root(jobs_root: &FsPath) -> Result<PathBuf, SidecarError> {
    if jobs_root.as_os_str().is_empty() {
        return Err(SidecarError::Config(
            "jobs_root must be non-empty in governed mode".to_string(),
        ));
    }
    let canonical = jobs_root.canonicalize().map_err(|error| {
        SidecarError::Config(format!(
            "jobs_root {} could not be canonicalized: {error}",
            jobs_root.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(SidecarError::Config(format!(
            "jobs_root {} is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn resolve_jobs_root_expression(
    source_id: &str,
    label: &str,
    jobs_root: &FsPath,
    expression: &FsPath,
) -> Result<PathBuf, SidecarError> {
    if expression.is_absolute() {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must be relative to jobs_root"
        )));
    }
    if expression.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    }) {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must not escape jobs_root"
        )));
    }
    let joined = jobs_root.join(expression);
    let canonical_expression = joined.canonicalize().map_err(|error| {
        SidecarError::Config(format!(
            "source {source_id} {label} {} could not be canonicalized: {error}",
            expression.display()
        ))
    })?;
    if !canonical_expression.starts_with(jobs_root) {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} symlink escapes jobs_root"
        )));
    }
    Ok(canonical_expression)
}

fn validate_sha256_uri(value: &str) -> Result<(), &'static str> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("missing sha256 prefix");
    };
    if hex.len() != 64 {
        return Err("digest must be 64 lowercase hex characters");
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("digest must be lowercase hex");
    }
    Ok(())
}

fn validate_source_adaptor(
    source_id: &str,
    label: &str,
    adaptor: &str,
) -> Result<(), SidecarError> {
    if adaptor.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must be pinned"
        )));
    }
    adaptor_pin_version(adaptor).ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} {label} {adaptor} must include a version pin"
        ))
    })?;
    Ok(())
}

fn resolve_auth_tokens(config: &SidecarConfig) -> Result<Vec<ResolvedBearerToken>, SidecarError> {
    let mut tokens = Vec::with_capacity(config.auth.bearer_tokens.len());
    for token in &config.auth.bearer_tokens {
        let Some(hash_env) = &token.hash_env else {
            return Err(SidecarError::Config(format!(
                "bearer token {} must set hash_env",
                token.id
            )));
        };
        let fingerprint =
            std::env::var(hash_env).map_err(|_| SidecarError::MissingTokenHashEnv {
                token_id: token.id.clone(),
                env: hash_env.clone(),
            })?;
        parse_fingerprint(&fingerprint).map_err(|_| SidecarError::InvalidTokenHashEnv {
            token_id: token.id.clone(),
            env: hash_env.clone(),
        })?;
        tokens.push(ResolvedBearerToken { fingerprint });
    }
    Ok(tokens)
}

fn adaptor_pin_version(adaptor: &str) -> Option<&str> {
    let module_specifier = adaptor
        .split_once('=')
        .map_or(adaptor, |(module, _)| module);
    let (name, version) = module_specifier.rsplit_once('@')?;
    if name.is_empty() || version.trim().is_empty() {
        return None;
    }
    Some(version)
}

async fn verify_openfn_runtime(config: &SidecarConfig) -> Result<(), SidecarError> {
    let mut version_args = config.worker.version_args.clone().unwrap_or_else(|| {
        let mut args = config.worker.args.clone();
        args.push("--version".to_string());
        args
    });
    if version_args.is_empty() {
        version_args.push("--version".to_string());
    }

    let output = tokio::time::timeout(Duration::from_secs(5), async {
        Command::new(&config.worker.command)
            .args(&version_args)
            .output()
            .await
    })
    .await
    .map_err(|_| SidecarError::StartupCheck("OpenFn version check timed out".to_string()))?
    .map_err(|_| SidecarError::StartupCheck("OpenFn version check failed".to_string()))?;

    if !output.status.success() {
        return Err(SidecarError::StartupCheck(
            "OpenFn version check exited unsuccessfully".to_string(),
        ));
    }

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    let reported = combined.split_whitespace().collect::<Vec<_>>();
    for expected in [
        format!("cli_build_tool={}", config.openfn.cli_build_tool),
        format!("runtime={}", config.openfn.runtime),
    ] {
        if !reported.iter().any(|reported| *reported == expected) {
            return Err(SidecarError::StartupCheck(format!(
                "OpenFn version check did not report required pin {expected}"
            )));
        }
    }
    for source in config.sources.values() {
        for adaptor in source_adaptors(source) {
            let pinned_version = adaptor_pin_version(adaptor).ok_or_else(|| {
                SidecarError::StartupCheck(format!(
                    "OpenFn adaptor {adaptor} is missing a version pin"
                ))
            })?;
            let expected_prefix = format!("{adaptor}:");
            let Some(reported_suffix) = reported
                .iter()
                .find_map(|reported| reported.strip_prefix(&expected_prefix))
            else {
                return Err(SidecarError::StartupCheck(format!(
                    "OpenFn version check did not report required adaptor {adaptor}"
                )));
            };
            let installed_version = reported_suffix
                .split_once('=')
                .map_or(reported_suffix, |(version, _)| version);
            if installed_version != pinned_version {
                return Err(SidecarError::StartupCheck(format!(
                    "OpenFn adaptor {adaptor} resolved to version {installed_version}, expected {pinned_version}"
                )));
            }
        }
    }

    Ok(())
}

fn source_adaptors(source: &SourceConfig) -> Vec<&str> {
    source
        .workflow
        .steps
        .iter()
        .flat_map(|step| step.adaptors.iter().map(String::as_str))
        .collect()
}

fn add_source_execution(request: &mut Value, config: &SidecarConfig, source: &SourceConfig) {
    let Some(object) = request.as_object_mut() else {
        return;
    };
    object.insert(
        "workflow".to_string(),
        json!(workflow_for_worker(config, &source.workflow)),
    );
}

fn workflow_for_worker(
    config: &SidecarConfig,
    workflow: &SourceWorkflowConfig,
) -> SourceWorkflowConfig {
    let Some(jobs_root) = &config.jobs_root else {
        return workflow.clone();
    };
    let mut workflow = workflow.clone();
    for step in &mut workflow.steps {
        if step.expression.is_relative() {
            step.expression = jobs_root.join(&step.expression);
        }
    }
    workflow
}

fn load_credentials(config: &SidecarConfig) -> Result<BTreeMap<String, Value>, SidecarError> {
    let mut credentials = BTreeMap::new();
    for (source_id, source) in &config.sources {
        let raw =
            std::env::var(&source.credential_env).map_err(|_| SidecarError::MissingCredential {
                source_id: source_id.clone(),
                env: source.credential_env.clone(),
            })?;
        let credential =
            serde_json::from_str(&raw).map_err(|error| SidecarError::CredentialJson {
                source_id: source_id.clone(),
                env: source.credential_env.clone(),
                source: error,
            })?;
        validate_credential_base_url(source_id, source, &credential)?;
        credentials.insert(source_id.clone(), credential);
    }
    Ok(credentials)
}

fn validate_credential_base_url(
    source_id: &str,
    source: &SourceConfig,
    credential: &Value,
) -> Result<(), SidecarError> {
    if source.allowed_base_urls.is_empty() {
        return Ok(());
    }
    let Some(base_url) = credential.get("baseUrl").and_then(Value::as_str) else {
        return Err(SidecarError::CredentialBaseUrl {
            source_id: source_id.to_string(),
            env: source.credential_env.clone(),
        });
    };
    let normalized = base_url.trim_end_matches('/');
    if source
        .allowed_base_urls
        .iter()
        .map(|allowed| allowed.trim_end_matches('/'))
        .any(|allowed| allowed == normalized)
    {
        Ok(())
    } else {
        Err(SidecarError::CredentialBaseUrl {
            source_id: source_id.to_string(),
            env: source.credential_env.clone(),
        })
    }
}

async fn run_smoke_lookups(state: &Arc<AppState>) -> Result<(), SidecarError> {
    for (source_id, source) in &state.config.sources {
        let Some(smoke) = &source.smoke_lookup else {
            continue;
        };
        let deadline =
            Instant::now() + Duration::from_millis(state.config.limits.liveness_window_ms.max(1));
        let retry_after = Duration::from_secs(state.config.limits.retry_after_seconds.max(1));
        let mut last_reason = "smoke lookup was not attempted".to_string();
        let mut attempted = false;

        loop {
            if attempted && Instant::now() >= deadline {
                return Err(SidecarError::SmokeLookup {
                    source_id: source_id.clone(),
                    reason: last_reason,
                });
            }
            attempted = true;

            let mut request = json!({
                "source_id": source_id,
                "dataset": source.dataset,
                "entity": source.entity,
                "lookup": {
                    "field": smoke.field,
                    "value": smoke.value,
                },
                "fields": smoke.fields,
                "limit": 1,
                "purpose": smoke.purpose,
                "correlation_id": "startup-smoke",
                "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
            });
            add_source_execution(&mut request, &state.config, source);
            match state.pool.execute_json(request).await {
                Ok(response) => {
                    if let Some(records) = response.get("data").and_then(Value::as_array) {
                        if records.iter().any(|record| {
                            record
                                .get(&smoke.field)
                                .and_then(Value::as_str)
                                .is_some_and(|value| value == smoke.value)
                        }) {
                            break;
                        }
                        last_reason = format!(
                            "worker response did not contain expected smoke record for {}",
                            smoke.field
                        );
                    } else if let Some(code) =
                        response.pointer("/error/code").and_then(Value::as_str)
                    {
                        last_reason = response
                            .pointer("/error/message")
                            .and_then(Value::as_str)
                            .map(|message| format!("worker returned error {code}: {message}"))
                            .unwrap_or_else(|| format!("worker returned error {code}"));
                    } else {
                        last_reason = "worker response did not contain data array".to_string();
                    }
                }
                Err(error) => {
                    last_reason = smoke_error_reason(&error);
                }
            }

            if Instant::now() >= deadline {
                return Err(SidecarError::SmokeLookup {
                    source_id: source_id.clone(),
                    reason: last_reason,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(retry_after.min(remaining)).await;
        }
    }
    Ok(())
}

fn smoke_error_reason(error: &WorkerError) -> String {
    match error {
        WorkerError::Saturated { .. } => "worker pool saturated".to_string(),
        WorkerError::CircuitOpen { .. } => "worker replacement circuit breaker is open".to_string(),
        WorkerError::Timeout { .. } => "worker timed out".to_string(),
        WorkerError::RequestTooLarge { .. } => "worker request too large".to_string(),
        WorkerError::StdoutTooLarge { .. } => "worker output exceeded byte limit".to_string(),
        WorkerError::InvalidOutput { .. } => "worker output was not valid JSON".to_string(),
        WorkerError::WorkerExited { .. } => "worker exited before returning data".to_string(),
        WorkerError::Io { .. } => "worker IO failed".to_string(),
        WorkerError::InvalidConfig { .. } => "worker pool config is invalid".to_string(),
        WorkerError::Encode { .. } => "worker request could not be encoded".to_string(),
        WorkerError::Spawn { .. } => "worker could not be spawned".to_string(),
    }
}

async fn healthz(State(state): State<Arc<AppState>>) -> Response {
    let snapshot = state.pool.snapshot().await;
    if snapshot.idle_workers + snapshot.in_flight < snapshot.max_workers {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "worker pool capacity degraded",
        );
    }
    let liveness_window = Duration::from_millis(state.config.limits.liveness_window_ms);
    if snapshot
        .active_for
        .is_some_and(|active_for| active_for > liveness_window)
        && snapshot
            .completed_within
            .is_none_or(|completed_within| completed_within > liveness_window)
    {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "worker pool liveness failed",
        );
    }
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

async fn ready(State(state): State<Arc<AppState>>) -> Response {
    if state.pool.check_ready().await {
        let mut body = json!({ "status": "ready" });
        if let Some(assurance) = &state.config.assurance {
            body["config_hash"] = json!(assurance.config_hash);
            body["expression_hashes_verified"] = json!(assurance.expression_hashes_verified);
            body["runtime_verified"] = json!(assurance.runtime_verified);
            body["smoke_verified"] = json!(assurance.smoke_verified);
        }
        (StatusCode::OK, Json(body)).into_response()
    } else {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "worker pool is not fully available",
        )
    }
}

async fn assurance(State(state): State<Arc<AppState>>) -> Response {
    match &state.config.assurance {
        Some(assurance) => (StatusCode::OK, Json(assurance)).into_response(),
        None => problem(
            StatusCode::NOT_FOUND,
            "governed sidecar assurance is not configured",
        ),
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let snapshot = state.pool.snapshot().await;
    let mut body = format!(
        concat!(
            "# TYPE registry_notary_openfn_sidecar_workers gauge\n",
            "registry_notary_openfn_sidecar_workers{{state=\"max\"}} {}\n",
            "registry_notary_openfn_sidecar_workers{{state=\"idle\"}} {}\n",
            "registry_notary_openfn_sidecar_workers{{state=\"in_flight\"}} {}\n",
            "# TYPE registry_notary_openfn_sidecar_worker_completions_total counter\n",
            "registry_notary_openfn_sidecar_worker_completions_total {}\n",
            "# TYPE registry_notary_openfn_sidecar_worker_replacements_total counter\n",
            "registry_notary_openfn_sidecar_worker_replacements_total {}\n",
            "# TYPE registry_notary_openfn_sidecar_worker_circuit_open gauge\n",
            "registry_notary_openfn_sidecar_worker_circuit_open {}\n"
        ),
        snapshot.max_workers,
        snapshot.idle_workers,
        snapshot.in_flight,
        snapshot.completed_total,
        snapshot.replacements_total,
        u8::from(snapshot.circuit_open)
    );
    let metrics = state.metrics.lock().await;
    if !metrics.is_empty() {
        body.push_str("# TYPE registry_notary_openfn_sidecar_lookup_total counter\n");
        body.push_str("# TYPE registry_notary_openfn_sidecar_lookup_duration_ms_total counter\n");
    }
    for (key, value) in metrics.iter() {
        body.push_str(&format!(
            "registry_notary_openfn_sidecar_lookup_total{{source_id=\"{}\",outcome=\"{}\"}} {}\n",
            escape_metric_label(&key.source_id),
            escape_metric_label(&key.outcome),
            value.count
        ));
        body.push_str(&format!(
            "registry_notary_openfn_sidecar_lookup_duration_ms_total{{source_id=\"{}\",outcome=\"{}\"}} {}\n",
            escape_metric_label(&key.source_id),
            escape_metric_label(&key.outcome),
            value.duration_ms_total
        ));
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

async fn lookup(
    State(state): State<Arc<AppState>>,
    Path((dataset, entity)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let started_at = Instant::now();
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let Some(purpose) = headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return problem(StatusCode::BAD_REQUEST, "missing Data-Purpose");
    };

    let Some((source_id, source)) = state
        .config
        .sources
        .iter()
        .find(|(_, source)| source.dataset == dataset && source.entity == entity)
    else {
        return problem(StatusCode::NOT_FOUND, "source route not found");
    };

    let query = match validate_query(&state, raw_query.as_deref(), query) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let correlation_id = headers
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let mut request = json!({
        "source_id": source_id,
        "dataset": dataset,
        "entity": entity,
        "lookup": {
            "field": query.lookup_field,
            "value": query.lookup_value,
        },
        "fields": query.fields,
        "limit": query.limit,
        "purpose": purpose,
        "correlation_id": correlation_id.clone(),
        "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
    });
    add_source_execution(&mut request, &state.config, source);

    let worker_execution = match state.pool.execute_json_with_metadata(request).await {
        Ok(execution) => execution,
        Err(error) => {
            let worker_id = error.worker_id();
            record_metric(&state, source_id, "worker_error", started_at.elapsed()).await;
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "worker_error",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar lookup failed"
            );
            return worker_error_response(error, state.config.limits.retry_after_seconds);
        }
    };

    let response = normalize_worker_response(worker_execution.value, &query.fields, query.limit);
    let outcome = if response.status().is_success() {
        "success"
    } else {
        "source_error"
    };
    record_metric(&state, source_id, outcome, started_at.elapsed()).await;
    info!(
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        source_id = source_id.as_str(),
        outcome,
        worker_id = worker_execution.worker_id,
        status = response.status().as_u16(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "sidecar lookup completed"
    );
    response
}

async fn batch_match(
    State(state): State<Arc<AppState>>,
    Path((dataset, entity)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let started_at = Instant::now();
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let Some(purpose) = headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return problem(StatusCode::BAD_REQUEST, "missing Data-Purpose");
    };

    let Some((source_id, source)) = state
        .config
        .sources
        .iter()
        .find(|(_, source)| source.dataset == dataset && source.entity == entity)
    else {
        return problem(StatusCode::NOT_FOUND, "source route not found");
    };

    let body = match parse_batch_match_body(&state, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if let Err(response) = validate_batch_match_request(&state, &body) {
        return *response;
    }

    let correlation_id = headers
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut request = json!({
        "mode": "batch_match",
        "source_id": source_id,
        "dataset": dataset,
        "entity": entity,
        "query_signature": body.query_signature,
        "items": body.items,
        "fields": body.fields,
        "purpose": purpose,
        "correlation_id": correlation_id.clone(),
        "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
    });
    add_source_execution(&mut request, &state.config, source);

    let worker_execution = match state.pool.execute_json_with_metadata(request).await {
        Ok(execution) => execution,
        Err(error) => {
            let worker_id = error.worker_id();
            record_metric(
                &state,
                source_id,
                "batch_worker_error",
                started_at.elapsed(),
            )
            .await;
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "batch_worker_error",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar batch match failed"
            );
            return worker_error_response(error, state.config.limits.retry_after_seconds);
        }
    };

    let response = normalize_batch_worker_response(
        worker_execution.value,
        &body.fields,
        &body
            .items
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>(),
    );
    let outcome = if response.status().is_success() {
        "batch_success"
    } else {
        "batch_source_error"
    };
    record_metric(&state, source_id, outcome, started_at.elapsed()).await;
    info!(
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        source_id = source_id.as_str(),
        outcome,
        worker_id = worker_execution.worker_id,
        status = response.status().as_u16(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "sidecar batch match completed"
    );
    response
}

async fn parse_batch_match_body(
    state: &AppState,
    body: Body,
) -> Result<BatchMatchRequest, Box<Response>> {
    let limit = state.config.limits.max_request_bytes;
    let bytes = to_bytes(body, limit).await.map_err(|_| {
        Box::new(problem(
            StatusCode::BAD_REQUEST,
            "request body exceeds configured byte limit",
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        Box::new(problem(
            StatusCode::BAD_REQUEST,
            "invalid batch match request",
        ))
    })
}

async fn record_metric(state: &AppState, source_id: &str, outcome: &str, duration: Duration) {
    let key = MetricKey {
        source_id: source_id.to_string(),
        outcome: outcome.to_string(),
    };
    let mut metrics = state.metrics.lock().await;
    let value = metrics.entry(key).or_default();
    value.count = value.count.saturating_add(1);
    value.duration_ms_total = value
        .duration_ms_total
        .saturating_add(duration.as_millis() as u64);
}

fn escape_metric_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(Box::new(unauthorized()));
    };
    let token = parse_bearer_token(raw).map_err(|_| Box::new(unauthorized()))?;
    if state
        .auth_tokens
        .iter()
        .any(|configured| verify_api_key(token, &configured.fingerprint).unwrap_or(false))
    {
        Ok(())
    } else {
        Err(Box::new(problem(
            StatusCode::FORBIDDEN,
            "sidecar token rejected",
        )))
    }
}

fn unauthorized() -> Response {
    let mut response = problem(
        StatusCode::UNAUTHORIZED,
        "missing or malformed sidecar token",
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

struct LookupQuery {
    lookup_field: String,
    lookup_value: String,
    fields: Vec<String>,
    limit: usize,
}

fn validate_query(
    state: &AppState,
    raw_query: Option<&str>,
    query: HashMap<String, String>,
) -> Result<LookupQuery, Box<Response>> {
    if raw_query
        .map(|raw| raw.len() > state.config.limits.max_request_bytes)
        .unwrap_or(false)
    {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "query string too large",
        )));
    }

    for (key, value) in &query {
        if key.len() > state.config.limits.max_query_parameter_bytes
            || value.len() > state.config.limits.max_query_parameter_bytes
        {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "query parameter exceeds configured byte limit",
            )));
        }
    }

    let limit = query
        .get("limit")
        .map(|raw| raw.parse::<usize>())
        .transpose()
        .map_err(|_| Box::new(problem(StatusCode::BAD_REQUEST, "invalid limit")))?
        .unwrap_or(2);
    if limit > 2 {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "limit must be at most 2",
        )));
    }

    let fields = query
        .get("fields")
        .map(|raw| {
            raw.split(',')
                .filter(|field| !field.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if fields.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "fields projection is required",
        )));
    }

    let lookup_pairs = query
        .into_iter()
        .filter(|(key, _)| key != "fields" && key != "limit")
        .collect::<Vec<_>>();
    if lookup_pairs.len() != 1 {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "exactly one lookup predicate is required",
        )));
    }
    let (lookup_field, lookup_value) = lookup_pairs.into_iter().next().expect("one lookup pair");
    if lookup_value.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "lookup predicate value is required",
        )));
    }

    Ok(LookupQuery {
        lookup_field,
        lookup_value,
        fields,
        limit,
    })
}

fn validate_batch_match_request(
    state: &AppState,
    body: &BatchMatchRequest,
) -> Result<(), Box<Response>> {
    if body.fields.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "fields projection is required",
        )));
    }
    for field in &body.fields {
        if field.is_empty() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "fields projection entries are required",
            )));
        }
        if field.len() > state.config.limits.max_query_parameter_bytes {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "fields projection entry exceeds configured byte limit",
            )));
        }
    }
    if body.query_signature.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "query_signature is required",
        )));
    }
    if body.items.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "items are required",
        )));
    }
    if body.items.len() > state.config.limits.max_batch_items {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "batch item count exceeds configured limit",
        )));
    }
    for term in &body.query_signature {
        if term.field.is_empty() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "query_signature field is required",
            )));
        }
        if term.field.len() > state.config.limits.max_query_parameter_bytes {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "query_signature field exceeds configured byte limit",
            )));
        }
        if term.op != "eq" {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "unsupported query operation",
            )));
        }
    }
    let mut request_ids = BTreeSet::new();
    for item in &body.items {
        if item.id.is_empty() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "batch item id is required",
            )));
        }
        if !request_ids.insert(item.id.as_str()) {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "batch item id duplicated",
            )));
        }
        if item.values.len() != body.query_signature.len() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "batch item values must match query_signature length",
            )));
        }
        for value in &item.values {
            if value_query_size(value) > state.config.limits.max_query_parameter_bytes {
                return Err(Box::new(problem(
                    StatusCode::BAD_REQUEST,
                    "batch item value exceeds configured byte limit",
                )));
            }
        }
    }
    Ok(())
}

fn value_query_size(value: &Value) -> usize {
    match value {
        Value::String(value) => value.len(),
        other => other.to_string().len(),
    }
}

fn normalize_worker_response(response: Value, fields: &[String], limit: usize) -> Response {
    if let Some(error) = response.get("error").and_then(Value::as_object) {
        return target_error_response(error);
    }

    let Some(records) = response.get("data").and_then(Value::as_array) else {
        return problem(
            StatusCode::BAD_GATEWAY,
            "worker response missing data array",
        );
    };

    let projected = records
        .iter()
        .take(limit)
        .map(|record| project_record(record, fields))
        .collect::<Result<Vec<_>, _>>();
    match projected {
        Ok(data) => (StatusCode::OK, Json(json!({ "data": data }))).into_response(),
        Err(response) => *response,
    }
}

fn normalize_batch_worker_response(
    response: Value,
    fields: &[String],
    requested_ids: &[String],
) -> Response {
    let mut response = response;
    if let Some(error) = response.get("error").and_then(Value::as_object) {
        return target_error_response(error);
    }

    let Some(items) = response
        .as_object_mut()
        .and_then(|object| object.remove("items"))
        .and_then(|value| match value {
            Value::Array(items) => Some(items),
            _ => None,
        })
    else {
        return problem(
            StatusCode::BAD_GATEWAY,
            "worker response missing items array",
        );
    };

    let mut seen = BTreeSet::new();
    let mut by_id = BTreeMap::new();
    let requested = requested_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for item in items {
        let Value::Object(object) = item else {
            return problem(StatusCode::BAD_GATEWAY, "worker items must be JSON objects");
        };
        let Some(id) = object
            .get("id")
            .and_then(Value::as_str)
            .map(ToString::to_string)
        else {
            return problem(StatusCode::BAD_GATEWAY, "worker item missing id");
        };
        if !seen.insert(id.clone()) {
            return problem(StatusCode::BAD_GATEWAY, "worker item id duplicated");
        }
        if !requested.contains(id.as_str()) {
            return problem(StatusCode::BAD_GATEWAY, "worker item id was not requested");
        }
        by_id.insert(id, object);
    }

    let mut normalized = Vec::with_capacity(requested_ids.len());
    for id in requested_ids {
        let Some(mut item) = by_id.remove(id) else {
            normalized.push(json!({
                "id": id,
                "error": { "code": "source_unavailable" }
            }));
            continue;
        };
        if let Some(error) = item.get("error").and_then(Value::as_object) {
            normalized.push(json!({ "id": id, "error": normalize_item_error(error) }));
            continue;
        }
        let Some(records) = item.remove("data").and_then(|value| match value {
            Value::Array(records) => Some(records),
            _ => None,
        }) else {
            return problem(StatusCode::BAD_GATEWAY, "worker item missing data array");
        };
        let projected = records
            .into_iter()
            .take(2)
            .map(|record| project_record(&record, fields))
            .collect::<Result<Vec<_>, _>>();
        match projected {
            Ok(data) => normalized.push(json!({ "id": id, "data": data })),
            Err(response) => return *response,
        }
    }

    (StatusCode::OK, Json(json!({ "items": normalized }))).into_response()
}

fn normalize_item_error(error: &Map<String, Value>) -> Value {
    match error.get("code").and_then(Value::as_str) {
        Some("target_auth") => json!({ "code": "target_auth" }),
        Some("target_rate_limit") => {
            let mut normalized = json!({ "code": "target_rate_limit" });
            if let Some(retry_after) = error.get("retry_after_seconds").and_then(Value::as_u64) {
                normalized["retry_after_seconds"] = json!(retry_after);
            }
            normalized
        }
        _ => json!({ "code": "source_unavailable" }),
    }
}

fn project_record(record: &Value, fields: &[String]) -> Result<Value, Box<Response>> {
    let Some(object) = record.as_object() else {
        return Err(Box::new(problem(
            StatusCode::BAD_GATEWAY,
            "worker data records must be JSON objects",
        )));
    };
    if fields.is_empty() {
        return Ok(Value::Object(object.clone()));
    }

    let mut projected = Map::new();
    for field in fields {
        if let Some(value) = object.get(field) {
            projected.insert(field.clone(), value.clone());
        }
    }
    Ok(Value::Object(projected))
}

fn target_error_response(error: &Map<String, Value>) -> Response {
    match error.get("code").and_then(Value::as_str) {
        Some("target_rate_limit") => {
            let mut response = problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "target rate limited",
                "target_rate_limit",
            );
            if let Some(seconds) = error
                .get("retry_after_seconds")
                .and_then(Value::as_u64)
                .and_then(|seconds| HeaderValue::from_str(&seconds.to_string()).ok())
            {
                response.headers_mut().insert(header::RETRY_AFTER, seconds);
            }
            response
        }
        Some("target_auth") => {
            problem_with_code(StatusCode::BAD_GATEWAY, "target auth failed", "target_auth")
        }
        _ => problem_with_code(
            StatusCode::BAD_GATEWAY,
            "worker execution failed",
            "openfn_execution",
        ),
    }
}

fn worker_error_response(error: WorkerError, retry_after_seconds: u64) -> Response {
    match error {
        WorkerError::Saturated { .. } => {
            let mut response = problem(StatusCode::SERVICE_UNAVAILABLE, "worker pool saturated");
            if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        WorkerError::CircuitOpen { .. } => {
            let mut response = problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "worker replacement circuit breaker is open",
            );
            if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        WorkerError::Timeout { .. } => problem(StatusCode::GATEWAY_TIMEOUT, "worker timed out"),
        WorkerError::RequestTooLarge { .. } => {
            problem(StatusCode::BAD_REQUEST, "worker request too large")
        }
        WorkerError::StdoutTooLarge { .. }
        | WorkerError::InvalidOutput { .. }
        | WorkerError::WorkerExited { .. }
        | WorkerError::Io { .. } => problem(StatusCode::BAD_GATEWAY, "worker execution failed"),
        WorkerError::InvalidConfig { .. }
        | WorkerError::Encode { .. }
        | WorkerError::Spawn { .. } => problem(StatusCode::BAD_GATEWAY, "worker unavailable"),
    }
}

fn default_liveness_window_ms() -> u64 {
    30_000
}

fn default_retry_after_seconds() -> u64 {
    1
}

fn default_max_batch_items() -> usize {
    100
}

fn default_smoke_purpose() -> String {
    "startup-readiness-smoke".to_string()
}

fn problem(status: StatusCode, title: &'static str) -> Response {
    problem_body(status, title, None)
}

fn problem_with_code(status: StatusCode, title: &'static str, code: &'static str) -> Response {
    problem_body(status, title, Some(code))
}

fn problem_body(status: StatusCode, title: &'static str, code: Option<&'static str>) -> Response {
    let mut body = json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
    });
    if let Some(code) = code {
        body["code"] = json!(code);
    }
    (status, Json(body)).into_response()
}
