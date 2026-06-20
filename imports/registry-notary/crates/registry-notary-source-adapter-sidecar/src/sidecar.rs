use axum::{
    body::{to_bytes, Body},
    extract::{Path, Query, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{TimeDelta, Utc};
use crosswalk_core::{MappingRuntime, RuntimeOptions, StandaloneExpressionInput};
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
};
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
    convert::Infallible,
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroU64,
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tough::{
    editor::{signed::PathExists, RepositoryEditor},
    key_source::{KeySource, LocalKeySource},
    schema::Target,
};
use tower::ServiceExt;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tracing::{info, warn};

#[derive(Clone, Debug, Deserialize)]
pub struct SidecarConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub config_trust: Option<SidecarConfigTrustConfig>,
    pub limits: LimitConfig,
    pub sources: BTreeMap<String, SourceConfig>,
    #[serde(skip)]
    pub assurance: Option<SidecarAssurance>,
    #[serde(skip)]
    governed_acceptance: Option<GovernedAcceptance>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_request_body_timeout_ms")]
    pub request_body_timeout_ms: u64,
    #[serde(default = "default_http1_header_read_timeout_ms")]
    pub http1_header_read_timeout_ms: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_timeout_ms: Option<u64>,
    pub max_worker_memory_mb: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceConfig {
    pub dataset: String,
    pub entity: String,
    #[serde(default)]
    pub engine: SourceEngine,
    #[serde(default)]
    pub credential_env: String,
    #[serde(default)]
    pub credential_public_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "SourceBatchConfig::is_default")]
    pub batch: SourceBatchConfig,
    #[serde(default, skip_serializing_if = "SourceRuntimeLimitConfig::is_default")]
    pub limits: SourceRuntimeLimitConfig,
    #[serde(default)]
    pub allowed_base_urls: Vec<String>,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    #[serde(default)]
    pub allow_insecure_private_network: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_json: Option<HttpJsonSourceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_flow: Option<HttpFlowSourceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fhir: Option<FhirSourceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<SourceCacheConfig>,
    #[serde(default)]
    pub smoke_lookup: Option<SmokeLookupConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEngine {
    #[default]
    HttpJson,
    HttpFlow,
    Fhir,
}

impl SourceEngine {
    fn worker_id(self) -> &'static str {
        match self {
            SourceEngine::HttpJson => "http_json",
            SourceEngine::HttpFlow => "http_flow",
            SourceEngine::Fhir => "fhir",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirSourceConfig {
    #[serde(default = "default_fhir_version")]
    pub version: String,
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token_env: Option<String>,
    #[serde(default = "default_true")]
    pub forward_data_purpose: bool,
    #[serde(default = "default_fhir_search_method")]
    pub search_method: String,
    #[serde(default = "default_fhir_prefer_handling")]
    pub prefer_handling: String,
    #[serde(default = "default_fhir_accept")]
    pub accept: String,
    #[serde(default = "default_fhir_max_search_results")]
    pub max_search_results: usize,
    #[serde(default = "default_fhir_max_source_bundle_bytes")]
    pub max_source_bundle_bytes: usize,
    pub anchor: FhirNodeConfig,
    #[serde(default)]
    pub relations: Vec<FhirRelationConfig>,
    #[serde(default)]
    pub project: BTreeMap<String, FhirProjectionConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirNodeConfig {
    pub id: String,
    pub resource_type: String,
    #[serde(default = "default_fhir_cardinality_one")]
    pub cardinality: String,
    #[serde(default)]
    pub search: Vec<FhirSearchParamConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirRelationConfig {
    pub id: String,
    pub resource_type: String,
    #[serde(default = "default_fhir_cardinality_one")]
    pub cardinality: String,
    #[serde(default)]
    pub search: Vec<FhirSearchParamConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirSearchParamConfig {
    pub param: String,
    #[serde(rename = "type")]
    pub search_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from_lookup: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from_node: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirProjectionConfig {
    pub node: String,
    pub pointer: String,
    #[serde(default, rename = "default", skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceBatchConfig {
    #[serde(default)]
    pub mode: SourceBatchMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parallel: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceBatchMode {
    #[default]
    SequentialLookup,
    WorkflowBatch,
    ParallelLookup,
    NativeBatch,
}

impl SourceBatchConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRuntimeLimitConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_second: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
}

impl SourceRuntimeLimitConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpJsonSourceConfig {
    #[serde(default)]
    pub method: HttpJsonMethod,
    pub base_url: HttpJsonCelExpression,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default)]
    pub headers: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<HttpJsonAuthConfig>,
    pub response: HttpJsonResponseConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<HttpJsonBatchConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceCacheConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_match_ttl_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_found_ttl_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpJsonMethod {
    #[default]
    Get,
    Post,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpJsonCelExpression {
    pub cel: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpJsonAuthConfig {
    #[serde(rename = "type")]
    pub kind: HttpJsonAuthKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<HttpJsonSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<HttpJsonSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<HttpJsonSecretRef>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpJsonAuthKind {
    Bearer,
    Basic,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpJsonSecretRef {
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpJsonResponseConfig {
    pub records: HttpJsonCelExpression,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpJsonBatchConfig {
    #[serde(default)]
    pub method: HttpJsonMethod,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default)]
    pub headers: BTreeMap<String, HttpJsonCelExpression>,
    pub response: HttpJsonBatchResponseConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpJsonBatchResponseConfig {
    pub records: HttpJsonCelExpression,
    pub record_key: HttpJsonCelExpression,
    pub item_key: HttpJsonCelExpression,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpFlowSourceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    pub steps: Vec<HttpFlowStepConfig>,
    pub output: HttpFlowOutputConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpFlowStepConfig {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<HttpJsonCelExpression>,
    pub request: HttpFlowRequestConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpFlowResponseConfig>,
    #[serde(default)]
    pub on_status: BTreeMap<String, HttpFlowStatusAction>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpFlowRequestConfig {
    #[serde(default)]
    pub method: HttpJsonMethod,
    pub base_url: String,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default)]
    pub headers: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<HttpJsonAuthConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HttpFlowResponseConfig {
    #[serde(default)]
    pub bind: BTreeMap<String, HttpJsonCelExpression>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpFlowOutputConfig {
    pub records: HttpJsonCelExpression,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpFlowStatusAction {
    Continue,
    SourceUnavailable,
    TargetAuth,
    TargetRateLimit,
    Timeout,
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
    sources: BTreeMap<String, SourceConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmokeLookupConfig {
    pub field: String,
    pub value: String,
    #[serde(default)]
    pub query_values: BTreeMap<String, String>,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchQueryTerm {
    field: String,
    op: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchMatchItem {
    id: String,
    values: Vec<Value>,
}

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("sidecar config error: {0}")]
    Config(String),
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
    #[error("credential env {env} for source {source_id} has disallowed or missing baseUrl for allowed_base_urls")]
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
    config: Arc<SidecarConfig>,
    auth_tokens: Arc<Vec<ResolvedBearerToken>>,
    fhir_bearer_tokens: Arc<BTreeMap<String, String>>,
    credentials: Arc<BTreeMap<String, Value>>,
    source_limiters: Arc<BTreeMap<String, Arc<Semaphore>>>,
    source_runtime: Arc<BTreeMap<String, Arc<SourceRuntimeState>>>,
    http_json_clients: Arc<Mutex<BTreeMap<String, reqwest::Client>>>,
    metrics: Arc<Mutex<BTreeMap<MetricKey, MetricValue>>>,
}

struct SourceRuntimeState {
    source_config_hash: String,
    rate_limiter: Option<Mutex<TokenBucket>>,
    backoff_until: Mutex<Option<Instant>>,
    cache: Mutex<BTreeMap<String, CacheEntry>>,
}

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

struct CacheEntry {
    expires_at: Instant,
    last_accessed: Instant,
    value: Value,
}

impl SourceRuntimeState {
    fn new(source: &SourceConfig) -> Result<Self, SidecarError> {
        let source_config_hash =
            registry_platform_config::sha256_uri(&serde_json::to_vec(source).map_err(|error| {
                SidecarError::Config(format!("source config hash failed: {error}"))
            })?);
        let limits = &source.limits;
        let rate_limiter = limits.requests_per_second.map(|requests_per_second| {
            let capacity = limits.burst.unwrap_or(requests_per_second).max(1) as f64;
            Mutex::new(TokenBucket {
                capacity,
                tokens: capacity,
                refill_per_second: requests_per_second.max(1) as f64,
                last_refill: Instant::now(),
            })
        });
        Ok(Self {
            source_config_hash,
            rate_limiter,
            backoff_until: Mutex::new(None),
            cache: Mutex::new(BTreeMap::new()),
        })
    }
}

impl TokenBucket {
    fn try_take(&mut self, now: Instant) -> Result<(), Duration> {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let missing = 1.0 - self.tokens;
            let wait_seconds = (missing / self.refill_per_second).max(0.001);
            Err(Duration::from_secs_f64(wait_seconds))
        }
    }
}

#[derive(Clone)]
struct ResolvedBearerToken {
    fingerprint: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MetricKey {
    source_id: String,
    outcome: String,
    engine: Option<String>,
    step_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct MetricValue {
    count: u64,
    duration_ms_total: u64,
    items_total: u64,
}

struct SourceExecution {
    value: Value,
    worker_id: String,
}

struct PreparedHttpJsonRequest {
    url: reqwest::Url,
    client: reqwest::Client,
}

// All variants are http_json-engine error categories; the shared prefix is
// intentional now that the OpenFn engine (and its differently-prefixed
// variants) is retired. Renaming would churn ~110 call sites for no clarity.
#[allow(clippy::enum_variant_names)]
enum SourceExecutionError {
    HttpJson,
    HttpJsonBadRequest,
    HttpJsonTimeout,
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

pub fn render_governed_runtime_target_json(raw_manifest: &str) -> Result<Vec<u8>, SidecarError> {
    let config: SidecarConfig = serde_norway::from_str(raw_manifest)
        .map_err(|error| SidecarError::Config(error.to_string()))?;
    let target = GovernedRuntimeTarget {
        schema: "registry.notary.openfn_sidecar.runtime.v1".to_string(),
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
    Ok(json!({
        "verified": true,
        "target_name": target_name,
        "config_hash": registry_platform_config::sha256_uri(&target_bytes),
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
        limits: target.limits,
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
            request_timeout_ms: default_request_timeout_ms(),
            request_body_timeout_ms: default_request_body_timeout_ms(),
            http1_header_read_timeout_ms: default_http1_header_read_timeout_ms(),
            max_connections: default_max_connections(),
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
        limits: target.limits.clone(),
        sources: target.sources.clone(),
        assurance: None,
        governed_acceptance: None,
    };
    validate_config(&config)
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
    let auth_tokens = resolve_auth_tokens(&config)?;
    let fhir_bearer_tokens = resolve_fhir_bearer_tokens(&config)?;
    let request_timeout = Duration::from_millis(config.server.request_timeout_ms);
    let request_body_timeout = Duration::from_millis(config.server.request_body_timeout_ms);

    let credentials = load_credentials(&config)?;
    let source_limiters = config
        .sources
        .iter()
        .map(|(source_id, source)| {
            let max_in_flight = source
                .limits
                .max_in_flight
                .unwrap_or(config.limits.max_workers);
            (source_id.clone(), Arc::new(Semaphore::new(max_in_flight)))
        })
        .collect();
    let source_runtime = config
        .sources
        .iter()
        .map(|(source_id, source)| {
            SourceRuntimeState::new(source).map(|runtime| (source_id.clone(), Arc::new(runtime)))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let state = Arc::new(AppState {
        config: Arc::new(config),
        auth_tokens: Arc::new(auth_tokens),
        fhir_bearer_tokens: Arc::new(fhir_bearer_tokens),
        credentials: Arc::new(credentials),
        source_limiters: Arc::new(source_limiters),
        source_runtime: Arc::new(source_runtime),
        http_json_clients: Arc::new(Mutex::new(BTreeMap::new())),
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
        .with_state(state)
        .layer(middleware::from_fn(enforce_uri_limit))
        .layer(RequestBodyTimeoutLayer::new(request_body_timeout))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        )))
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

pub async fn run(config: SidecarConfig) -> Result<(), Box<dyn std::error::Error>> {
    let bind = config.server.bind;
    let max_connections = config.server.max_connections;
    let request_timeout_ms = config.server.request_timeout_ms;
    let request_body_timeout_ms = config.server.request_body_timeout_ms;
    let http1_header_read_timeout =
        Duration::from_millis(config.server.http1_header_read_timeout_ms);
    let http2_keep_alive_interval = http1_header_read_timeout;
    let app = sidecar_router(config).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local_addr = listener.local_addr()?;
    let connection_permits = Arc::new(Semaphore::new(max_connections));
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut tasks = JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    tracing::info!(
        %local_addr,
        max_connections,
        request_timeout_ms,
        request_body_timeout_ms,
        http1_header_read_timeout_ms = %http1_header_read_timeout.as_millis(),
        "registry notary source adapter sidecar listening"
    );

    loop {
        while let Some(joined) = tasks.try_join_next() {
            if let Err(error) = joined {
                warn!(error = %error, bind = %local_addr, "sidecar HTTP connection task failed");
            }
        }

        let permit = tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!(
                    "registry notary source adapter sidecar shutdown signal received"
                );
                break;
            }
            permit = Arc::clone(&connection_permits).acquire_owned() => {
                match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                }
            }
        };
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!(
                    "registry notary source adapter sidecar shutdown signal received"
                );
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        let app = app.clone();
                        let close_rx = shutdown_rx.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            serve_sidecar_connection(
                                stream,
                                remote_addr,
                                app,
                                http1_header_read_timeout,
                                http2_keep_alive_interval,
                                close_rx,
                            )
                            .await;
                        });
                    }
                    Err(error) => {
                        warn!(error = %error, bind = %local_addr, "failed to accept sidecar connection");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
        }
    }

    drop(shutdown_tx);
    while let Some(joined) = tasks.join_next().await {
        if let Err(error) = joined {
            warn!(error = %error, bind = %local_addr, "sidecar HTTP connection task failed during shutdown");
        }
    }
    Ok(())
}

async fn serve_sidecar_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    app: Router,
    http1_header_read_timeout: Duration,
    http2_keep_alive_interval: Duration,
    mut close_rx: watch::Receiver<()>,
) {
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let app = app.clone();
        async move {
            let request = request.map(Body::new);
            match app.oneshot(request).await {
                Ok(response) => Ok::<_, Infallible>(response),
                Err(err) => match err {},
            }
        }
    });

    let mut builder = HyperBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(http1_header_read_timeout)
        .keep_alive(false);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(http2_keep_alive_interval)
        .keep_alive_timeout(http2_keep_alive_interval);

    let io = TokioIo::new(stream);
    let conn = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(conn);
    let mut shutdown_initiated = false;

    loop {
        tokio::select! {
            result = &mut conn => {
                if let Err(error) = result {
                    tracing::debug!(%remote_addr, %error, "sidecar HTTP connection ended with error");
                }
                break;
            }
            _ = close_rx.changed(), if !shutdown_initiated => {
                conn.as_mut().graceful_shutdown();
                shutdown_initiated = true;
            }
        }
    }
}

fn validate_config(config: &SidecarConfig) -> Result<(), SidecarError> {
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
    if config.server.request_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "server.request_timeout_ms must be greater than zero".to_string(),
        ));
    }
    if config.server.request_body_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "server.request_body_timeout_ms must be greater than zero".to_string(),
        ));
    }
    if config.server.http1_header_read_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "server.http1_header_read_timeout_ms must be greater than zero".to_string(),
        ));
    }
    if config.server.max_connections == 0 {
        return Err(SidecarError::Config(
            "server.max_connections must be greater than zero".to_string(),
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
        None => {}
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
    if config.limits.batch_timeout_ms == Some(0) {
        return Err(SidecarError::Config(
            "limits.batch_timeout_ms must be greater than zero".to_string(),
        ));
    }
    for (source_id, source) in &config.sources {
        if source.limits.max_in_flight == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.max_in_flight must be greater than zero"
            )));
        }
        if source.limits.requests_per_second == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.requests_per_second must be greater than zero"
            )));
        }
        if source.limits.burst == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.burst must be greater than zero"
            )));
        }
        if source.limits.burst.is_some() && source.limits.requests_per_second.is_none() {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.burst requires limits.requests_per_second"
            )));
        }
        if source.batch.max_parallel == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} batch.max_parallel must be greater than zero"
            )));
        }
        if let Some(cache) = &source.cache {
            if cache.exact_match_ttl_ms == Some(0) || cache.not_found_ttl_ms == Some(0) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} cache TTLs must be greater than zero"
                )));
            }
            if cache.max_entries == Some(0) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} cache.max_entries must be greater than zero"
                )));
            }
            if cache.exact_match_ttl_ms.is_none() && cache.not_found_ttl_ms.is_none() {
                return Err(SidecarError::Config(format!(
                    "source {source_id} cache must configure at least one TTL"
                )));
            }
        }
        validate_source_execution(source_id, source)?;
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

fn validate_source_execution(source_id: &str, source: &SourceConfig) -> Result<(), SidecarError> {
    match source.engine {
        SourceEngine::HttpJson => validate_http_json_source(source_id, source),
        SourceEngine::HttpFlow => validate_http_flow_source(source_id, source),
        SourceEngine::Fhir => validate_fhir_source(source_id, source),
    }
}

fn validate_http_json_source(source_id: &str, source: &SourceConfig) -> Result<(), SidecarError> {
    if source.http_flow.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow config is not valid when engine is http_json"
        )));
    }
    if source.fhir.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir config is not valid when engine is http_json"
        )));
    }
    if source.credential_env.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} credential_env is required for http_json sources"
        )));
    }
    let http_json = source.http_json.as_ref().ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} http_json config is required when engine is http_json"
        ))
    })?;
    if http_json.base_url.cel.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.base_url.cel must be non-empty"
        )));
    }
    validate_http_json_path(source_id, "http_json.path", &http_json.path)?;
    if source.batch.mode == SourceBatchMode::NativeBatch && http_json.batch.is_none() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.batch is required when batch.mode is native_batch"
        )));
    }
    if source.batch.mode == SourceBatchMode::WorkflowBatch {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.mode workflow_batch is only supported for OpenFn sources"
        )));
    }
    if source.batch.mode != SourceBatchMode::ParallelLookup && source.batch.max_parallel.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.max_parallel requires batch.mode parallel_lookup"
        )));
    }
    if http_json.response.records.cel.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.response.records.cel must be non-empty"
        )));
    }
    if source.allowed_base_urls.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} allowed_base_urls is required for http_json"
        )));
    }
    for (name, expr) in &http_json.query {
        validate_http_header_or_query_name(source_id, "query", name)?;
        validate_http_json_cel(source_id, &format!("http_json.query.{name}"), expr)?;
    }
    for (name, expr) in &http_json.headers {
        validate_http_header_or_query_name(source_id, "headers", name)?;
        validate_http_json_cel(source_id, &format!("http_json.headers.{name}"), expr)?;
    }
    validate_http_json_cel(source_id, "http_json.base_url", &http_json.base_url)?;
    validate_http_json_cel(
        source_id,
        "http_json.response.records",
        &http_json.response.records,
    )?;
    if let Some(batch) = &http_json.batch {
        validate_http_json_path(source_id, "http_json.batch.path", &batch.path)?;
        for (name, expr) in &batch.query {
            validate_http_header_or_query_name(source_id, "query", name)?;
            validate_http_json_cel(source_id, &format!("http_json.batch.query.{name}"), expr)?;
        }
        for (name, expr) in &batch.headers {
            validate_http_header_or_query_name(source_id, "headers", name)?;
            validate_http_json_cel(source_id, &format!("http_json.batch.headers.{name}"), expr)?;
        }
        validate_http_json_cel(
            source_id,
            "http_json.batch.response.records",
            &batch.response.records,
        )?;
        validate_http_json_cel(
            source_id,
            "http_json.batch.response.record_key",
            &batch.response.record_key,
        )?;
        validate_http_json_cel(
            source_id,
            "http_json.batch.response.item_key",
            &batch.response.item_key,
        )?;
    }
    if let Some(auth) = &http_json.auth {
        match auth.kind {
            HttpJsonAuthKind::Bearer => {
                validate_http_json_secret_ref(
                    source_id,
                    "http_json.auth.token.secret",
                    auth.token.as_ref(),
                )?;
            }
            HttpJsonAuthKind::Basic => {
                validate_http_json_secret_ref(
                    source_id,
                    "http_json.auth.username.secret",
                    auth.username.as_ref(),
                )?;
                validate_http_json_secret_ref(
                    source_id,
                    "http_json.auth.password.secret",
                    auth.password.as_ref(),
                )?;
            }
        }
    }
    Ok(())
}

fn validate_http_flow_source(source_id: &str, source: &SourceConfig) -> Result<(), SidecarError> {
    if source.http_json.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json config is not valid when engine is http_flow"
        )));
    }
    if source.fhir.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir config is not valid when engine is http_flow"
        )));
    }
    if source.credential_env.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} credential_env is required for http_flow sources"
        )));
    }
    if matches!(
        source.batch.mode,
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch
    ) {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.mode is not supported for http_flow sources"
        )));
    }
    if source.batch.mode != SourceBatchMode::ParallelLookup && source.batch.max_parallel.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.max_parallel requires batch.mode parallel_lookup"
        )));
    }
    if source.allowed_base_urls.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} allowed_base_urls is required for http_flow"
        )));
    }
    let flow = source.http_flow.as_ref().ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} http_flow config is required when engine is http_flow"
        ))
    })?;
    if flow.steps.len() < 2 {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow.steps must contain at least two steps"
        )));
    }
    if flow.steps.len() > 5 {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow.steps must not contain more than five steps"
        )));
    }
    if let Some(max_steps) = flow.max_steps {
        if max_steps == 0 || max_steps > 5 {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow.max_steps must be between one and five"
            )));
        }
        if flow.steps.len() > max_steps {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow.steps exceeds http_flow.max_steps"
            )));
        }
    }
    if flow.timeout_ms == Some(0) {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow.timeout_ms must be greater than zero"
        )));
    }
    validate_http_json_cel(source_id, "http_flow.output.records", &flow.output.records)?;

    let mut step_ids = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    for step in &flow.steps {
        validate_http_flow_identifier(source_id, "http_flow step id", &step.id)?;
        if !step_ids.insert(step.id.clone()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow step {} is duplicated",
                step.id
            )));
        }
        if let Some(when) = &step.when {
            validate_http_json_cel(
                source_id,
                &format!("http_flow.steps.{}.when", step.id),
                when,
            )?;
        }
        if step.request.method != HttpJsonMethod::Get {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow step {} only supports GET in v1",
                step.id
            )));
        }
        validate_http_flow_base_url(source_id, source, &step.id, &step.request.base_url)?;
        validate_http_json_path(
            source_id,
            &format!("http_flow.steps.{}.request.path", step.id),
            &step.request.path,
        )?;
        for (name, expr) in &step.request.query {
            validate_http_header_or_query_name(source_id, "query", name)?;
            validate_http_json_cel(
                source_id,
                &format!("http_flow.steps.{}.request.query.{name}", step.id),
                expr,
            )?;
        }
        for (name, expr) in &step.request.headers {
            validate_http_header_or_query_name(source_id, "headers", name)?;
            validate_http_json_cel(
                source_id,
                &format!("http_flow.steps.{}.request.headers.{name}", step.id),
                expr,
            )?;
        }
        if let Some(response) = &step.response {
            for (name, expr) in &response.bind {
                validate_http_flow_identifier(source_id, "http_flow binding", name)?;
                if http_flow_reserved_binding(name) {
                    return Err(SidecarError::Config(format!(
                        "source {source_id} http_flow binding {name} is reserved"
                    )));
                }
                if !bindings.insert(name.clone()) {
                    return Err(SidecarError::Config(format!(
                        "source {source_id} http_flow binding {name} is duplicated"
                    )));
                }
                validate_http_json_cel(
                    source_id,
                    &format!("http_flow.steps.{}.response.bind.{name}", step.id),
                    expr,
                )?;
            }
        }
        for status in step.on_status.keys() {
            let status_code = status.parse::<u16>().map_err(|_| {
                SidecarError::Config(format!(
                    "source {source_id} http_flow step {} on_status keys must be HTTP status codes",
                    step.id
                ))
            })?;
            if !(100..=599).contains(&status_code) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} http_flow step {} on_status keys must be HTTP status codes",
                    step.id
                )));
            }
        }
        if let Some(auth) = &step.request.auth {
            match auth.kind {
                HttpJsonAuthKind::Bearer => {
                    validate_http_json_secret_ref(
                        source_id,
                        &format!("http_flow.steps.{}.request.auth.token.secret", step.id),
                        auth.token.as_ref(),
                    )?;
                }
                HttpJsonAuthKind::Basic => {
                    validate_http_json_secret_ref(
                        source_id,
                        &format!("http_flow.steps.{}.request.auth.username.secret", step.id),
                        auth.username.as_ref(),
                    )?;
                    validate_http_json_secret_ref(
                        source_id,
                        &format!("http_flow.steps.{}.request.auth.password.secret", step.id),
                        auth.password.as_ref(),
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_fhir_source(source_id: &str, source: &SourceConfig) -> Result<(), SidecarError> {
    if source.http_json.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json config is not valid when engine is fhir"
        )));
    }
    if source.http_flow.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow config is not valid when engine is fhir"
        )));
    }
    if source.cache.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} cache is not supported for fhir sources"
        )));
    }
    if matches!(
        source.batch.mode,
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch
    ) {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.mode is not supported for fhir sources"
        )));
    }
    if source.batch.mode != SourceBatchMode::ParallelLookup && source.batch.max_parallel.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.max_parallel requires batch.mode parallel_lookup"
        )));
    }
    if source.allowed_base_urls.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} allowed_base_urls is required for fhir"
        )));
    }
    let fhir = source.fhir.as_ref().ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} fhir config is required when engine is fhir"
        ))
    })?;
    if fhir.version != "R4" {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.version must be R4"
        )));
    }
    if fhir.search_method != "get" {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.search_method must be get"
        )));
    }
    if fhir.max_search_results == 0 {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.max_search_results must be greater than zero"
        )));
    }
    if fhir
        .bearer_token_env
        .as_deref()
        .is_some_and(|env| env.trim().is_empty())
    {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.bearer_token_env must not be empty"
        )));
    }
    let base_url = reqwest::Url::parse(&fhir.base_url).map_err(|_| {
        SidecarError::Config(format!(
            "source {source_id} fhir.base_url must be an absolute URL"
        ))
    })?;
    validate_fhir_base_url_policy(source_id, source, &base_url)?;
    ensure_allowed_base_url(source_id, source, &base_url)?;
    validate_fhir_node(source_id, "anchor", &fhir.anchor)?;
    let mut node_ids = BTreeSet::from([fhir.anchor.id.as_str()]);
    for relation in &fhir.relations {
        validate_fhir_node(
            source_id,
            &format!("relation {}", relation.id),
            &FhirNodeConfig {
                id: relation.id.clone(),
                resource_type: relation.resource_type.clone(),
                cardinality: relation.cardinality.clone(),
                search: relation.search.clone(),
            },
        )?;
        if !node_ids.insert(relation.id.as_str()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir node id {} is duplicated",
                relation.id
            )));
        }
    }
    for (field, projection) in &fhir.project {
        if field.trim().is_empty() {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.project field must not be empty"
            )));
        }
        if !node_ids.contains(projection.node.as_str()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.project.{field}.node is not defined"
            )));
        }
        if !projection.pointer.starts_with('/') {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.project.{field}.pointer must be a JSON Pointer"
            )));
        }
        if let Some(value) = &projection.default_value {
            if value.is_object() || value.is_array() {
                return Err(SidecarError::Config(format!(
                    "source {source_id} fhir.project.{field}.default must be scalar"
                )));
            }
        }
    }
    Ok(())
}

fn validate_fhir_node(
    source_id: &str,
    label: &str,
    node: &FhirNodeConfig,
) -> Result<(), SidecarError> {
    if node.id.trim().is_empty() || node.resource_type.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} id and resource_type are required"
        )));
    }
    if !is_fhir_resource_type(&node.resource_type) {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} resource_type is invalid"
        )));
    }
    if !matches!(
        node.cardinality.as_str(),
        "one" | "zero_or_one" | "one_or_more" | "any"
    ) {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} cardinality is unsupported"
        )));
    }
    if node.search.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} search must not be empty"
        )));
    }
    for search in &node.search {
        if search.param.trim().is_empty() {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir {label} search param is required"
            )));
        }
        if !matches!(
            search.search_type.as_str(),
            "token" | "reference" | "string" | "date" | "code"
        ) {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir {label} search type {} is unsupported",
                search.search_type
            )));
        }
        let value_sources = [
            search.value.is_some(),
            search.value_from_lookup.unwrap_or(false),
            search.value_from_query.is_some(),
            search.value_from_node.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if value_sources != 1 {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir {label} search {} must declare exactly one value source",
                search.param
            )));
        }
    }
    Ok(())
}

fn is_fhir_resource_type(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| first.is_ascii_uppercase())
        && chars.all(|ch| ch.is_ascii_alphanumeric())
}

fn validate_fhir_base_url_policy(
    source_id: &str,
    source: &SourceConfig,
    base_url: &reqwest::Url,
) -> Result<(), SidecarError> {
    let Some(host) = base_url.host_str() else {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.base_url must include a host"
        )));
    };
    if host.eq_ignore_ascii_case("metadata.google.internal") {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.base_url must not target metadata services"
        )));
    }
    match base_url.scheme() {
        "https" => {}
        "http" => {
            let ip = host.parse::<IpAddr>().ok().map(canonical_ip);
            if ip.is_some_and(is_cloud_metadata_ip) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} fhir.base_url must not target metadata services"
                )));
            }
            let loopback = ip.is_some_and(|ip| ip.is_loopback()) || is_localhost_host(host);
            if loopback {
                if !(source.allow_insecure_localhost || source.allow_insecure_private_network) {
                    return Err(SidecarError::Config(format!(
                        "source {source_id} fhir.base_url requires allow_insecure_localhost for loopback http"
                    )));
                }
            } else if !source.allow_insecure_private_network {
                return Err(SidecarError::Config(format!(
                    "source {source_id} fhir.base_url must use https or explicitly allowed private-network http"
                )));
            } else {
                // Runtime request preparation resolves the hostname and applies
                // the private-network and metadata-service IP policy before any
                // outbound request is sent.
            }
        }
        _ => {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.base_url must use https or explicitly allowed private-network http"
            )));
        }
    }
    Ok(())
}

fn validate_http_flow_base_url(
    source_id: &str,
    source: &SourceConfig,
    step_id: &str,
    base_url: &str,
) -> Result<(), SidecarError> {
    let base = reqwest::Url::parse(base_url).map_err(|_| {
        SidecarError::Config(format!(
            "source {source_id} http_flow step {step_id} request.base_url must be a URL"
        ))
    })?;
    ensure_allowed_base_url(source_id, source, &base)
}

fn validate_http_flow_identifier(
    source_id: &str,
    label: &str,
    value: &str,
) -> Result<(), SidecarError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(SidecarError::Config(format!(
            "source {source_id} {label} contains an invalid identifier"
        )))
    }
}

fn http_flow_reserved_binding(value: &str) -> bool {
    matches!(
        value,
        "source_id"
            | "dataset"
            | "entity"
            | "lookup"
            | "fields"
            | "limit"
            | "purpose"
            | "correlation_id"
            | "credential_public"
            | "body"
            | "status"
            | "headers"
            | "items"
            | "query_signature"
            | "item"
            | "record"
    )
}

fn validate_http_json_path(source_id: &str, label: &str, path: &str) -> Result<(), SidecarError> {
    if path.trim().is_empty()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path
            .trim_start_matches('/')
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must be an absolute path under the configured base_url"
        )));
    }
    Ok(())
}

fn validate_http_json_secret_ref(
    source_id: &str,
    label: &str,
    secret_ref: Option<&HttpJsonSecretRef>,
) -> Result<(), SidecarError> {
    let secret_ref = secret_ref.ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} {label} must name one top-level credential field"
        ))
    })?;
    if secret_ref.secret.trim().is_empty() || secret_ref.secret.contains('.') {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must name one top-level credential field"
        )));
    }
    Ok(())
}

fn validate_http_json_cel(
    source_id: &str,
    label: &str,
    expr: &HttpJsonCelExpression,
) -> Result<(), SidecarError> {
    if expr.cel.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label}.cel must be non-empty"
        )));
    }
    Ok(())
}

fn validate_http_header_or_query_name(
    source_id: &str,
    section: &str,
    name: &str,
) -> Result<(), SidecarError> {
    if name.trim().is_empty()
        || name
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.{section} contains an invalid name"
        )));
    }
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

fn resolve_fhir_bearer_tokens(
    config: &SidecarConfig,
) -> Result<BTreeMap<String, String>, SidecarError> {
    let mut tokens = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.engine != SourceEngine::Fhir {
            continue;
        }
        let Some(env) = source
            .fhir
            .as_ref()
            .and_then(|fhir| fhir.bearer_token_env.as_ref())
        else {
            continue;
        };
        if tokens.contains_key(env) {
            continue;
        }
        let token = std::env::var(env).ok().filter(|token| !token.is_empty());
        let Some(token) = token else {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.bearer_token_env {env} is missing or empty"
            )));
        };
        tokens.insert(env.clone(), token);
    }
    Ok(tokens)
}

async fn execute_source_json(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    match source.engine {
        SourceEngine::HttpJson => execute_http_json(state, source_id, source, request).await,
        SourceEngine::HttpFlow => execute_http_flow(state, source_id, source, request).await,
        SourceEngine::Fhir => execute_fhir(state, source_id, source, request).await,
    }
}

async fn execute_fhir(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_fhir_batch_match(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "fhir".to_string(),
        });
    }

    let lookup = request
        .get("lookup")
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_field = lookup
        .get("field")
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_value = lookup
        .get("value")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let fields = request_fields(&request)?;
    let limit = request
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(2);
    let purpose = request.get("purpose").and_then(Value::as_str).unwrap_or("");
    let query_values = request_query_values(&request)?;
    let data = execute_fhir_lookup(
        state,
        source_id,
        source,
        lookup_field,
        lookup_value,
        &query_values,
        &fields,
        limit,
        purpose,
    )
    .await?;
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "fhir".to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn execute_fhir_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    lookup_field: &str,
    lookup_value: Value,
    query_values: &BTreeMap<String, String>,
    fields: &[String],
    limit: usize,
    purpose: &str,
) -> Result<Vec<Value>, SourceExecutionError> {
    let fhir = source.fhir.as_ref().ok_or(SourceExecutionError::HttpJson)?;
    let mut nodes = BTreeMap::<String, Vec<Value>>::new();
    let anchor = search_fhir_node(
        state,
        source_id,
        source,
        fhir,
        &fhir.anchor,
        lookup_field,
        &lookup_value,
        query_values,
        &nodes,
        purpose,
    )
    .await?;
    match anchor.len() {
        0 => return Ok(Vec::new()),
        1 => {
            nodes.insert(fhir.anchor.id.clone(), anchor);
        }
        _ => {
            nodes.insert(fhir.anchor.id.clone(), anchor);
            return Ok(project_fhir_records(fhir, &nodes, fields, limit));
        }
    }

    for relation in &fhir.relations {
        let node = FhirNodeConfig {
            id: relation.id.clone(),
            resource_type: relation.resource_type.clone(),
            cardinality: relation.cardinality.clone(),
            search: relation.search.clone(),
        };
        let resources = search_fhir_node(
            state,
            source_id,
            source,
            fhir,
            &node,
            lookup_field,
            &lookup_value,
            query_values,
            &nodes,
            purpose,
        )
        .await?;
        if resources.is_empty() {
            if matches!(relation.cardinality.as_str(), "zero_or_one" | "any") {
                nodes.insert(relation.id.clone(), resources);
                continue;
            }
            return Ok(Vec::new());
        }
        if matches!(relation.cardinality.as_str(), "one" | "zero_or_one") && resources.len() > 1 {
            nodes.insert(relation.id.clone(), resources);
            return Ok(project_fhir_records(fhir, &nodes, fields, limit));
        }
        nodes.insert(relation.id.clone(), resources);
    }

    Ok(project_fhir_records(fhir, &nodes, fields, limit))
}

#[allow(clippy::too_many_arguments)]
async fn search_fhir_node(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    fhir: &FhirSourceConfig,
    node: &FhirNodeConfig,
    lookup_field: &str,
    lookup_value: &Value,
    query_values: &BTreeMap<String, String>,
    nodes: &BTreeMap<String, Vec<Value>>,
    purpose: &str,
) -> Result<Vec<Value>, SourceExecutionError> {
    let prepared = prepare_http_json_request(
        state,
        source_id,
        source,
        &fhir.base_url,
        &node.resource_type,
    )
    .await?;
    let mut url = prepared.url;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("_count", &(fhir.max_search_results + 1).to_string());
        for search in &node.search {
            let value = fhir_search_value(search, lookup_field, lookup_value, query_values, nodes)?;
            query.append_pair(&search.param, &value);
        }
    }
    let mut request = prepared
        .client
        .get(url)
        .header("accept", fhir.accept.as_str());
    if fhir.forward_data_purpose {
        request = request.header("data-purpose", purpose);
    }
    if let Some(env) = &fhir.bearer_token_env {
        let token = state
            .fhir_bearer_tokens
            .get(env)
            .ok_or(SourceExecutionError::HttpJson)?;
        request = request.bearer_auth(token);
    }
    if !fhir.prefer_handling.is_empty() {
        request = request.header("prefer", format!("handling={}", fhir.prefer_handling));
    }
    if acquire_http_json_rate_or_error(state, source_id)
        .await
        .is_some()
    {
        return Err(SourceExecutionError::HttpJsonTimeout);
    }
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(SourceExecutionError::HttpJson);
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Err(SourceExecutionError::HttpJsonTimeout);
    }
    if !status.is_success() {
        return Err(SourceExecutionError::HttpJson);
    }
    let max_bytes = fhir
        .max_source_bundle_bytes
        .min(state.config.limits.max_output_bytes);
    let body = read_limited_json_response(response, max_bytes).await?;
    fhir_bundle_match_resources(&body, &node.resource_type, fhir.max_search_results + 1)
}

fn fhir_search_value(
    search: &FhirSearchParamConfig,
    lookup_field: &str,
    lookup_value: &Value,
    query_values: &BTreeMap<String, String>,
    nodes: &BTreeMap<String, Vec<Value>>,
) -> Result<String, SourceExecutionError> {
    let raw = if let Some(value) = &search.value {
        value.clone()
    } else if search.value_from_lookup.unwrap_or(false) {
        let _ = lookup_field;
        value_to_query_string(lookup_value)?
    } else if let Some(field) = &search.value_from_query {
        query_values
            .get(field)
            .cloned()
            .ok_or(SourceExecutionError::HttpJsonBadRequest)?
    } else if let Some(value_from_node) = &search.value_from_node {
        fhir_value_from_node(value_from_node, nodes)?
    } else {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    };
    match search.search_type.as_str() {
        "token" => Ok(search
            .system
            .as_ref()
            .map(|system| format!("{system}|{raw}"))
            .unwrap_or(raw)),
        "reference" | "string" | "date" | "code" => Ok(raw),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

fn fhir_value_from_node(
    value_from_node: &str,
    nodes: &BTreeMap<String, Vec<Value>>,
) -> Result<String, SourceExecutionError> {
    let (node_id, selector) = value_from_node
        .split_once('.')
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let resource = nodes
        .get(node_id)
        .and_then(|resources| resources.first())
        .ok_or(SourceExecutionError::HttpJson)?;
    match selector {
        "id" => resource
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(SourceExecutionError::HttpJson),
        "reference" => {
            let resource_type = resource
                .get("resourceType")
                .and_then(Value::as_str)
                .ok_or(SourceExecutionError::HttpJson)?;
            let id = resource
                .get("id")
                .and_then(Value::as_str)
                .ok_or(SourceExecutionError::HttpJson)?;
            Ok(format!("{resource_type}/{id}"))
        }
        pointer if pointer.starts_with('/') => resource
            .pointer(pointer)
            .ok_or(SourceExecutionError::HttpJson)
            .and_then(value_to_query_string),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

fn value_to_query_string(value: &Value) -> Result<String, SourceExecutionError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(_) | Value::Bool(_) => Ok(value.to_string()),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

fn fhir_bundle_match_resources(
    body: &Value,
    resource_type: &str,
    limit: usize,
) -> Result<Vec<Value>, SourceExecutionError> {
    if body.get("resourceType").and_then(Value::as_str) != Some("Bundle")
        || body.get("type").and_then(Value::as_str) != Some("searchset")
    {
        return Err(SourceExecutionError::HttpJson);
    }
    let entries = body
        .get("entry")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut resources = Vec::new();
    for entry in entries {
        if entry.pointer("/search/mode").and_then(Value::as_str) != Some("match") {
            continue;
        }
        let Some(resource) = entry.get("resource") else {
            continue;
        };
        if resource.get("resourceType").and_then(Value::as_str) != Some(resource_type) {
            return Err(SourceExecutionError::HttpJson);
        }
        resources.push(resource.clone());
        if resources.len() >= limit {
            break;
        }
    }
    Ok(resources)
}

fn project_fhir_records(
    fhir: &FhirSourceConfig,
    nodes: &BTreeMap<String, Vec<Value>>,
    fields: &[String],
    limit: usize,
) -> Vec<Value> {
    let row_count = nodes
        .values()
        .map(Vec::len)
        .max()
        .unwrap_or_default()
        .min(limit);
    (0..row_count)
        .map(|index| project_fhir_record(fhir, nodes, fields, index))
        .collect()
}

fn project_fhir_record(
    fhir: &FhirSourceConfig,
    nodes: &BTreeMap<String, Vec<Value>>,
    fields: &[String],
    index: usize,
) -> Value {
    let mut record = Map::new();
    for field in fields {
        let Some(projection) = fhir.project.get(field) else {
            continue;
        };
        let Some(resource) = nodes
            .get(&projection.node)
            .and_then(|resources| resources.get(index).or_else(|| resources.first()))
        else {
            continue;
        };
        if let Some(value) = resource.pointer(&projection.pointer) {
            record.insert(field.clone(), value.clone());
        } else if let Some(value) = &projection.default_value {
            record.insert(field.clone(), value.clone());
        }
    }
    Value::Object(record)
}

async fn execute_fhir_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_fhir_sequential_batch_match(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_fhir_parallel_batch_match(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

async fn execute_fhir_sequential_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let query_signature: Vec<BatchQueryTerm> =
        serde_json::from_value(query_signature).map_err(|_| SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let items: Vec<BatchMatchItem> =
        serde_json::from_value(items).map_err(|_| SourceExecutionError::HttpJson)?;
    let fields = request_fields(request)?;
    let purpose = request.get("purpose").and_then(Value::as_str).unwrap_or("");
    let mut output = Vec::with_capacity(items.len());
    for item in &items {
        let query = fhir_batch_item_query(source, &query_signature, item);
        let Ok((lookup_field, lookup_value, query_values)) = query else {
            output.push(json!({
                "id": item.id,
                "error": { "code": "source_unavailable" }
            }));
            continue;
        };
        let result = execute_fhir_lookup(
            state,
            source_id,
            source,
            &lookup_field,
            Value::String(lookup_value),
            &query_values,
            &fields,
            2,
            purpose,
        )
        .await;
        match result {
            Ok(data) => output.push(json!({ "id": item.id, "data": data })),
            Err(_) => output.push(json!({
                "id": item.id,
                "error": { "code": "source_unavailable" }
            })),
        }
    }
    Ok(json!({ "items": output }))
}

async fn execute_fhir_parallel_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let query_signature: Vec<BatchQueryTerm> =
        serde_json::from_value(query_signature).map_err(|_| SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let items: Vec<BatchMatchItem> =
        serde_json::from_value(items).map_err(|_| SourceExecutionError::HttpJson)?;
    let fields = Arc::new(request_fields(request)?);
    let purpose = Arc::new(
        request
            .get("purpose")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    );
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = Arc::new(source.clone());
    let source_id = source_id.to_string();
    let query_signature = Arc::new(query_signature);
    let mut tasks = JoinSet::new();
    let requested_ids = items.iter().map(|item| item.id.clone()).collect::<Vec<_>>();
    for (idx, item) in items.into_iter().enumerate() {
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = Arc::clone(&source);
        let task_source_id = source_id.clone();
        let task_query_signature = Arc::clone(&query_signature);
        let task_fields = Arc::clone(&fields);
        let task_purpose = Arc::clone(&purpose);
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let id = item.id.clone();
            let response = match fhir_batch_item_query(
                task_source.as_ref(),
                task_query_signature.as_ref(),
                &item,
            ) {
                Ok((lookup_field, lookup_value, query_values)) => {
                    match execute_fhir_lookup(
                        &task_state,
                        &task_source_id,
                        task_source.as_ref(),
                        &lookup_field,
                        Value::String(lookup_value),
                        &query_values,
                        task_fields.as_ref(),
                        2,
                        task_purpose.as_ref(),
                    )
                    .await
                    {
                        Ok(data) => json!({ "id": id, "data": data }),
                        Err(_) => json!({
                            "id": id,
                            "error": { "code": "source_unavailable" }
                        }),
                    }
                }
                Err(_) => json!({
                    "id": id,
                    "error": { "code": "source_unavailable" }
                }),
            };
            Ok::<_, SourceExecutionError>((idx, response))
        });
    }

    let mut output = vec![Value::Null; requested_ids.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, response) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        output[idx] = response;
    }
    for (idx, response) in output.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source_unavailable" }
            });
        }
    }
    Ok(json!({ "items": output }))
}

fn fhir_batch_item_query(
    source: &SourceConfig,
    query_signature: &[BatchQueryTerm],
    item: &BatchMatchItem,
) -> Result<(String, String, BTreeMap<String, String>), SourceExecutionError> {
    let mut query_values = BTreeMap::new();
    for (term, value) in query_signature.iter().zip(item.values.iter()) {
        query_values.insert(term.field.clone(), value_to_query_string(value)?);
    }
    primary_lookup_value(source, &query_values).ok_or(SourceExecutionError::HttpJsonBadRequest)
}

fn request_fields(request: &Value) -> Result<Vec<String>, SourceExecutionError> {
    request
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?
        .iter()
        .map(|field| {
            field
                .as_str()
                .map(str::to_string)
                .ok_or(SourceExecutionError::HttpJsonBadRequest)
        })
        .collect()
}

fn request_query_values(request: &Value) -> Result<BTreeMap<String, String>, SourceExecutionError> {
    request
        .get("query_values")
        .and_then(Value::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key.clone(), value.to_string()))
                        .ok_or(SourceExecutionError::HttpJsonBadRequest)
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(BTreeMap::new()))
}

async fn execute_http_json(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_http_json_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "http_json".to_string(),
        });
    }
    let data = execute_http_json_lookup(state, source_id, source, &request).await?;
    if data.get("error").is_some() {
        return Ok(SourceExecution {
            value: data,
            worker_id: "http_json".to_string(),
        });
    }
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "http_json".to_string(),
    })
}

async fn execute_http_flow(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_http_flow_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "http_flow".to_string(),
        });
    }
    let data = execute_http_flow_lookup_with_timeout(state, source_id, source, &request).await?;
    if data.get("error").is_some() {
        return Ok(SourceExecution {
            value: data,
            worker_id: "http_flow".to_string(),
        });
    }
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "http_flow".to_string(),
    })
}

async fn execute_http_flow_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_http_flow_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_http_flow_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

async fn execute_http_flow_sequential_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let mut responses = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let lookup_request = http_json_item_lookup_request(source_id, request, lookup_field, item)?;
        let data = execute_http_flow_lookup_with_timeout(state, source_id, source, &lookup_request)
            .await?;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                return Ok(json!({ "error": error }));
            }
            responses.push(json!({ "id": id, "error": error }));
        } else {
            responses.push(json!({ "id": id, "data": data }));
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_http_flow_parallel_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = source.clone();
    let source_id = source_id.to_string();
    let mut tasks = JoinSet::new();
    let mut requested_ids = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?
            .to_string();
        requested_ids.push(id.clone());
        let lookup_request =
            http_json_item_lookup_request(&source_id, request, lookup_field, item)?;
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = source.clone();
        let task_source_id = source_id.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let data = execute_http_flow_lookup_with_timeout(
                &task_state,
                &task_source_id,
                &task_source,
                &lookup_request,
            )
            .await?;
            Ok::<_, SourceExecutionError>((idx, id, data))
        });
    }

    let mut responses = vec![Value::Null; items.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, id, data) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                tasks.abort_all();
                return Ok(json!({ "error": error }));
            }
            responses[idx] = json!({ "id": id, "error": error });
        } else {
            responses[idx] = json!({ "id": id, "data": data });
        }
    }

    for (idx, response) in responses.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source.unavailable" }
            });
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_http_json_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_http_json_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_http_json_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::NativeBatch => {
            execute_http_json_native_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

async fn execute_http_json_sequential_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let mut responses = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let lookup_request = http_json_item_lookup_request(source_id, request, lookup_field, item)?;
        let data = execute_http_json_lookup(state, source_id, source, &lookup_request).await?;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                return Ok(json!({ "error": error }));
            }
            responses.push(json!({ "id": id, "error": error }));
        } else {
            responses.push(json!({ "id": id, "data": data }));
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_http_json_parallel_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = Arc::new(source.clone());
    let source_id = source_id.to_string();
    let mut tasks = JoinSet::new();
    let mut requested_ids = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?
            .to_string();
        requested_ids.push(id.clone());
        let lookup_request =
            http_json_item_lookup_request(&source_id, request, lookup_field, item)?;
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = Arc::clone(&source);
        let task_source_id = source_id.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let data = execute_http_json_lookup(
                &task_state,
                &task_source_id,
                task_source.as_ref(),
                &lookup_request,
            )
            .await?;
            Ok::<_, SourceExecutionError>((idx, id, data))
        });
    }

    let mut responses = vec![Value::Null; items.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, id, data) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                tasks.abort_all();
                return Ok(json!({ "error": error }));
            }
            responses[idx] = json!({ "id": id, "error": error });
        } else {
            responses[idx] = json!({ "id": id, "data": data });
        }
    }

    for (idx, response) in responses.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source.unavailable" }
            });
        }
    }
    Ok(json!({ "items": responses }))
}

fn http_json_item_lookup_request(
    source_id: &str,
    batch_request: &Value,
    lookup_field: &str,
    item: &Value,
) -> Result<Value, SourceExecutionError> {
    let lookup_value = item
        .get("values")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .cloned()
        .ok_or(SourceExecutionError::HttpJson)?;
    Ok(json!({
        "source_id": source_id,
        "dataset": batch_request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": batch_request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": {
            "field": lookup_field,
            "value": lookup_value,
        },
        "fields": batch_request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": 2,
        "purpose": batch_request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": batch_request.get("correlation_id").cloned().unwrap_or(Value::Null),
    }))
}

async fn execute_http_json_native_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let http_json = source
        .http_json
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let batch = http_json
        .batch
        .as_ref()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let bindings = http_json_bindings(request, &public_credential, None);
    let base_url = eval_http_json_string(&http_json.base_url, bindings.clone())?;
    let prepared =
        prepare_http_json_request(state, source_id, source, &base_url, &batch.path).await?;
    let mut builder = match batch.method {
        HttpJsonMethod::Get => prepared.client.get(prepared.url),
        HttpJsonMethod::Post => prepared
            .client
            .post(prepared.url)
            .json(&http_json_batch_request_body(request)),
    };
    for (name, expr) in &batch.query {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.query(&[(name.as_str(), value)]);
    }
    for (name, expr) in &batch.headers {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.header(name.as_str(), value);
    }
    builder = apply_http_json_auth(builder, http_json.auth.as_ref(), &credential)?;
    if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
        return Ok(error);
    }

    let response = builder.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(json!({ "error": { "code": "source.target_auth" } }));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Ok(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after_seconds
            }
        }));
    }
    if !status.is_success() {
        return Ok(json!({ "error": { "code": "source.unavailable" } }));
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    fan_out_http_json_native_batch(batch, request, &public_credential, body)
}

fn fan_out_http_json_native_batch(
    batch: &HttpJsonBatchConfig,
    request: &Value,
    public_credential: &Value,
    body: Value,
) -> Result<Value, SourceExecutionError> {
    let records = eval_http_json_value(
        &batch.response.records,
        http_json_bindings(request, public_credential, Some(body)),
    )?;
    let records = records.as_array().ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;

    let mut request_keys = BTreeSet::new();
    for item in items {
        item.get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let key = eval_http_json_string(
            &batch.response.item_key,
            http_json_batch_item_bindings(request, public_credential, item, None),
        )?;
        request_keys.insert(key);
    }

    let mut grouped = BTreeMap::<String, Vec<Value>>::new();
    for record in records {
        let key = eval_http_json_string(
            &batch.response.record_key,
            http_json_batch_record_bindings(request, public_credential, record),
        )?;
        if request_keys.contains(&key) {
            grouped.entry(key).or_default().push(record.clone());
        }
    }

    let mut response_items = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let key = eval_http_json_string(
            &batch.response.item_key,
            http_json_batch_item_bindings(request, public_credential, item, None),
        )?;
        response_items.push(json!({
            "id": id,
            "data": grouped.get(&key).cloned().unwrap_or_default()
        }));
    }
    Ok(json!({ "items": response_items }))
}

fn http_json_batch_timeout(limits: &LimitConfig, item_count: usize) -> Duration {
    let computed_ms = limits
        .worker_timeout_ms
        .saturating_mul(item_count.max(1) as u64);
    let timeout_ms = limits
        .batch_timeout_ms
        .map_or(computed_ms, |configured| configured.min(computed_ms));
    Duration::from_millis(timeout_ms.max(1))
}

fn shared_credential_error(error: &Value) -> bool {
    matches!(
        error.get("code").and_then(Value::as_str),
        Some(
            "target_auth" | "target_rate_limit" | "source.target_auth" | "source.target_rate_limit"
        )
    )
}

async fn execute_http_flow_lookup_with_timeout(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let timeout = http_flow_timeout(state, source)?;
    match tokio::time::timeout(
        timeout,
        execute_http_flow_lookup(state, source_id, source, request),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            record_http_flow_metric(state, source_id, None, "flow_timeout", 1).await;
            Err(SourceExecutionError::HttpJsonTimeout)
        }
    }
}

fn http_flow_timeout(
    state: &AppState,
    source: &SourceConfig,
) -> Result<Duration, SourceExecutionError> {
    let flow = source
        .http_flow
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    Ok(Duration::from_millis(
        flow.timeout_ms
            .unwrap_or(state.config.limits.worker_timeout_ms)
            .max(1),
    ))
}

async fn execute_http_flow_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let flow = source
        .http_flow
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let cache_key = http_json_cache_key(state, source_id, request)?;
    if let Some(cache_key) = cache_key.as_deref() {
        if let Some(value) = http_json_cache_get(state, source_id, cache_key).await {
            return Ok(value);
        }
    }

    let mut bindings = http_flow_initial_bindings(flow);
    for step in &flow.steps {
        if let Some(when) = &step.when {
            if !eval_http_flow_bool(
                when,
                http_flow_bindings(request, &public_credential, &bindings, None, None),
            )? {
                record_http_flow_metric(state, source_id, Some(&step.id), "step_skipped", 1).await;
                continue;
            }
        }

        let prepared = prepare_http_json_request(
            state,
            source_id,
            source,
            &step.request.base_url,
            &step.request.path,
        )
        .await?;
        let mut builder = match step.request.method {
            HttpJsonMethod::Get => prepared.client.get(prepared.url),
            HttpJsonMethod::Post => return Err(SourceExecutionError::HttpJsonBadRequest),
        };
        let request_bindings =
            http_flow_bindings(request, &public_credential, &bindings, None, None);
        for (name, expr) in &step.request.query {
            let value = eval_http_json_string(expr, request_bindings.clone())?;
            builder = builder.query(&[(name.as_str(), value)]);
        }
        for (name, expr) in &step.request.headers {
            let value = eval_http_json_string(expr, request_bindings.clone())?;
            builder = builder.header(name.as_str(), value);
        }
        builder = apply_http_json_auth(builder, step.request.auth.as_ref(), &credential)?;
        if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
            return Ok(error);
        }
        let response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                SourceExecutionError::HttpJsonTimeout
            } else {
                SourceExecutionError::HttpJson
            }
        })?;
        let status = response.status();
        match http_flow_status_action(state, step, status, response.headers())? {
            HttpFlowStepOutcome::Bind => {
                let response_headers = http_flow_headers_value(response.headers());
                let body =
                    read_limited_json_response(response, state.config.limits.max_output_bytes)
                        .await?;
                let scope = http_flow_bindings(
                    request,
                    &public_credential,
                    &bindings,
                    Some(body),
                    Some((status, response_headers)),
                );
                let mut step_bindings = BTreeMap::new();
                if let Some(response) = &step.response {
                    for (name, expr) in &response.bind {
                        let value = eval_http_json_value(expr, scope.clone())?;
                        step_bindings.insert(name.clone(), value);
                    }
                }
                bindings.extend(step_bindings);
                record_http_flow_metric(state, source_id, Some(&step.id), "step_success", 1).await;
            }
            HttpFlowStepOutcome::Continue => {
                record_http_flow_metric(state, source_id, Some(&step.id), "step_skipped", 1).await;
            }
            HttpFlowStepOutcome::NotFound => {
                record_http_flow_metric(state, source_id, Some(&step.id), "flow_not_found", 1)
                    .await;
                if let Some(cache_key) = cache_key.as_deref() {
                    http_json_cache_put(state, source_id, source, cache_key, &json!([])).await;
                }
                return Ok(json!([]));
            }
            HttpFlowStepOutcome::Error(error) => {
                record_http_flow_metric(
                    state,
                    source_id,
                    Some(&step.id),
                    http_flow_error_metric_outcome(&error),
                    1,
                )
                .await;
                remember_source_backoff(state, source_id, &error).await;
                return Ok(error);
            }
        }
    }

    let records = eval_http_json_value(
        &flow.output.records,
        http_flow_bindings(request, &public_credential, &bindings, None, None),
    )?;
    if !records.is_array() {
        record_http_flow_metric(state, source_id, None, "flow_invalid_output", 1).await;
        return Err(SourceExecutionError::HttpJson);
    }
    if let Some(cache_key) = cache_key.as_deref() {
        http_json_cache_put(state, source_id, source, cache_key, &records).await;
    }
    Ok(records)
}

fn http_flow_error_metric_outcome(error: &Value) -> &'static str {
    match error
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
    {
        Some("source.target_auth") => "step_target_auth",
        Some("source.target_rate_limit") => "step_target_rate_limit",
        Some("source.timeout") => "step_source_timeout",
        Some("source.unavailable") => "step_source_unavailable",
        _ => "step_source_error",
    }
}

enum HttpFlowStepOutcome {
    Bind,
    Continue,
    NotFound,
    Error(Value),
}

fn http_flow_status_action(
    state: &AppState,
    step: &HttpFlowStepConfig,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<HttpFlowStepOutcome, SourceExecutionError> {
    let action = step.on_status.get(&status.as_u16().to_string()).copied();
    match action {
        Some(HttpFlowStatusAction::Continue) => return Ok(HttpFlowStepOutcome::Continue),
        Some(HttpFlowStatusAction::SourceUnavailable) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.unavailable" } }),
            ));
        }
        Some(HttpFlowStatusAction::TargetAuth) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.target_auth" } }),
            ));
        }
        Some(HttpFlowStatusAction::TargetRateLimit) => {
            return Ok(HttpFlowStepOutcome::Error(json!({
                "error": {
                    "code": "source.target_rate_limit",
                    "retry_after_seconds": http_flow_retry_after_seconds(state, headers)
                }
            })));
        }
        Some(HttpFlowStatusAction::Timeout) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.timeout" } }),
            ));
        }
        None => {}
    }

    if status.is_success() {
        return Ok(HttpFlowStepOutcome::Bind);
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(HttpFlowStepOutcome::NotFound);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(HttpFlowStepOutcome::Error(
            json!({ "error": { "code": "source.target_auth" } }),
        ));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(HttpFlowStepOutcome::Error(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": http_flow_retry_after_seconds(state, headers)
            }
        })));
    }
    if status == reqwest::StatusCode::REQUEST_TIMEOUT {
        return Ok(HttpFlowStepOutcome::Error(
            json!({ "error": { "code": "source.timeout" } }),
        ));
    }
    Ok(HttpFlowStepOutcome::Error(
        json!({ "error": { "code": "source.unavailable" } }),
    ))
}

fn http_flow_retry_after_seconds(state: &AppState, headers: &reqwest::header::HeaderMap) -> u64 {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(state.config.limits.retry_after_seconds)
}

async fn execute_http_json_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let http_json = source
        .http_json
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let cache_key = http_json_cache_key(state, source_id, request)?;
    if let Some(cache_key) = cache_key.as_deref() {
        if let Some(value) = http_json_cache_get(state, source_id, cache_key).await {
            return Ok(value);
        }
        record_metric_with_items(state, source_id, "source_cache_miss", Duration::ZERO, 1).await;
    }
    let bindings = http_json_bindings(request, &public_credential, None);
    let base_url = eval_http_json_string(&http_json.base_url, bindings.clone())?;
    let prepared =
        prepare_http_json_request(state, source_id, source, &base_url, &http_json.path).await?;
    let mut builder = match http_json.method {
        HttpJsonMethod::Get => prepared.client.get(prepared.url),
        HttpJsonMethod::Post => prepared
            .client
            .post(prepared.url)
            .json(&http_json_request_body(request)),
    };
    for (name, expr) in &http_json.query {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.query(&[(name.as_str(), value)]);
    }
    for (name, expr) in &http_json.headers {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.header(name.as_str(), value);
    }
    builder = apply_http_json_auth(builder, http_json.auth.as_ref(), &credential)?;
    if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
        return Ok(error);
    }
    let response = builder.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(json!({ "error": { "code": "source.target_auth" } }));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Ok(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after_seconds
            }
        }));
    }
    if !status.is_success() {
        return Ok(json!({ "error": { "code": "source.unavailable" } }));
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    let records = eval_http_json_value(
        &http_json.response.records,
        http_json_bindings(request, &public_credential, Some(body)),
    )?;
    if !records.is_array() {
        return Err(SourceExecutionError::HttpJson);
    }
    if let Some(cache_key) = cache_key.as_deref() {
        http_json_cache_put(state, source_id, source, cache_key, &records).await;
    }
    Ok(records)
}

fn credential_secret<'a>(
    credential: &'a Value,
    secret_ref: &HttpJsonSecretRef,
) -> Result<&'a str, SourceExecutionError> {
    credential
        .get(&secret_ref.secret)
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)
}

fn http_json_request_body(request: &Value) -> Value {
    json!({
        "source_id": request.get("source_id").cloned().unwrap_or(Value::Null),
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": request.get("lookup").cloned().unwrap_or(Value::Null),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": request.get("limit").cloned().unwrap_or(Value::Null),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": request.get("correlation_id").cloned().unwrap_or(Value::Null),
    })
}

fn http_json_batch_request_body(request: &Value) -> Value {
    json!({
        "source_id": request.get("source_id").cloned().unwrap_or(Value::Null),
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "query_signature": request.get("query_signature").cloned().unwrap_or_else(|| json!([])),
        "items": request.get("items").cloned().unwrap_or_else(|| json!([])),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": request.get("correlation_id").cloned().unwrap_or(Value::Null),
    })
}

fn apply_http_json_auth(
    mut builder: reqwest::RequestBuilder,
    auth: Option<&HttpJsonAuthConfig>,
    credential: &Value,
) -> Result<reqwest::RequestBuilder, SourceExecutionError> {
    if let Some(auth) = auth {
        match auth.kind {
            HttpJsonAuthKind::Bearer => {
                let token_ref = auth.token.as_ref().ok_or(SourceExecutionError::HttpJson)?;
                let token = credential_secret(credential, token_ref)?;
                builder = builder.bearer_auth(token);
            }
            HttpJsonAuthKind::Basic => {
                let username_ref = auth
                    .username
                    .as_ref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let password_ref = auth
                    .password
                    .as_ref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let username = credential_secret(credential, username_ref)?;
                let password = credential_secret(credential, password_ref)?;
                builder = builder.basic_auth(username, Some(password));
            }
        }
    }
    Ok(builder)
}

fn http_json_cache_key(
    state: &AppState,
    source_id: &str,
    request: &Value,
) -> Result<Option<String>, SourceExecutionError> {
    let Some(runtime) = state.source_runtime.get(source_id) else {
        return Err(SourceExecutionError::HttpJson);
    };
    let Some(source) = state.config.sources.get(source_id) else {
        return Err(SourceExecutionError::HttpJson);
    };
    if source.cache.is_none() {
        return Ok(None);
    }
    let key = json!({
        "source_config_hash": runtime.source_config_hash,
        "source_id": source_id,
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": request.get("lookup").cloned().unwrap_or(Value::Null),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": request.get("limit").cloned().unwrap_or(Value::Null),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
    });
    let bytes = serde_json::to_vec(&key).map_err(|_| SourceExecutionError::HttpJson)?;
    Ok(Some(registry_platform_config::sha256_uri(&bytes)))
}

async fn http_json_cache_get(state: &AppState, source_id: &str, key: &str) -> Option<Value> {
    let runtime = state.source_runtime.get(source_id)?;
    let now = Instant::now();
    let mut cache = runtime.cache.lock().await;
    let entry = cache.get_mut(key)?;
    if entry.expires_at <= now {
        cache.remove(key);
        return None;
    }
    entry.last_accessed = now;
    let value = entry.value.clone();
    drop(cache);
    record_metric_with_items(state, source_id, "source_cache_hit", Duration::ZERO, 1).await;
    Some(value)
}

async fn http_json_cache_put(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    key: &str,
    records: &Value,
) {
    let Some(ttl_ms) = http_json_cache_ttl_ms(source, records) else {
        return;
    };
    let Some(runtime) = state.source_runtime.get(source_id) else {
        return;
    };
    let mut cache = runtime.cache.lock().await;
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
    cache.insert(
        key.to_string(),
        CacheEntry {
            expires_at: now + Duration::from_millis(ttl_ms),
            last_accessed: now,
            value: records.clone(),
        },
    );
    evict_http_json_cache_entries(&mut cache, source.cache.as_ref());
}

fn http_json_cache_ttl_ms(source: &SourceConfig, records: &Value) -> Option<u64> {
    let cache = source.cache.as_ref()?;
    match records.as_array()?.len() {
        0 => cache.not_found_ttl_ms,
        1 => cache.exact_match_ttl_ms,
        _ => None,
    }
}

fn evict_http_json_cache_entries(
    cache: &mut BTreeMap<String, CacheEntry>,
    config: Option<&SourceCacheConfig>,
) {
    let max_entries = config
        .and_then(|cache| cache.max_entries)
        .unwrap_or(DEFAULT_SOURCE_CACHE_MAX_ENTRIES);
    if cache.len() <= max_entries {
        return;
    }
    let mut entries = cache
        .iter()
        .map(|(key, entry)| (key.clone(), entry.last_accessed))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, last_accessed)| *last_accessed);
    for (key, _) in entries.into_iter().take(cache.len() - max_entries) {
        cache.remove(&key);
    }
}

async fn read_limited_json_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, SourceExecutionError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(SourceExecutionError::HttpJson);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| SourceExecutionError::HttpJson)
}

fn public_credential(source: &SourceConfig, credential: &Value) -> Value {
    let Some(credential) = credential.as_object() else {
        return Value::Object(Map::new());
    };
    let mut public = Map::new();
    for field in &source.credential_public_fields {
        if let Some(value) = credential.get(field) {
            public.insert(field.clone(), value.clone());
        }
    }
    Value::Object(public)
}

fn http_json_bindings(
    request: &Value,
    public_credential: &Value,
    body: Option<Value>,
) -> StandaloneExpressionInput {
    let mut root_bindings = BTreeMap::new();
    for key in [
        "lookup",
        "fields",
        "limit",
        "purpose",
        "correlation_id",
        "dataset",
        "entity",
        "source_id",
        "items",
        "query_signature",
    ] {
        root_bindings.insert(
            key.to_string(),
            request.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    root_bindings.insert("credential_public".to_string(), public_credential.clone());
    root_bindings.insert("body".to_string(), body.unwrap_or(Value::Null));
    StandaloneExpressionInput::new(root_bindings)
}

fn http_flow_initial_bindings(flow: &HttpFlowSourceConfig) -> BTreeMap<String, Value> {
    let mut bindings = BTreeMap::new();
    for step in &flow.steps {
        if let Some(response) = &step.response {
            for name in response.bind.keys() {
                bindings.insert(name.clone(), Value::Null);
            }
        }
    }
    bindings
}

fn http_flow_bindings(
    request: &Value,
    public_credential: &Value,
    flow_bindings: &BTreeMap<String, Value>,
    body: Option<Value>,
    response_meta: Option<(reqwest::StatusCode, Value)>,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, body);
    for (name, value) in flow_bindings {
        bindings.root_bindings.insert(name.clone(), value.clone());
    }
    if let Some((status, headers)) = response_meta {
        bindings
            .root_bindings
            .insert("status".to_string(), json!(status.as_u16()));
        bindings
            .root_bindings
            .insert("headers".to_string(), headers);
    } else {
        bindings
            .root_bindings
            .insert("status".to_string(), Value::Null);
        bindings
            .root_bindings
            .insert("headers".to_string(), Value::Null);
    }
    bindings
}

fn http_flow_headers_value(headers: &reqwest::header::HeaderMap) -> Value {
    let mut object = Map::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            object.insert(name.as_str().to_ascii_lowercase(), json!(value));
        }
    }
    Value::Object(object)
}

fn http_json_batch_item_bindings(
    request: &Value,
    public_credential: &Value,
    item: &Value,
    body: Option<Value>,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, body);
    bindings
        .root_bindings
        .insert("item".to_string(), item.clone());
    bindings
}

fn http_json_batch_record_bindings(
    request: &Value,
    public_credential: &Value,
    record: &Value,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, None);
    bindings
        .root_bindings
        .insert("record".to_string(), record.clone());
    bindings
}

fn eval_http_json_string(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<String, SourceExecutionError> {
    match eval_http_json_value(expr, bindings)? {
        Value::String(value) => Ok(value),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(SourceExecutionError::HttpJson),
    }
}

fn eval_http_json_value(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<Value, SourceExecutionError> {
    let runtime = MappingRuntime::new(RuntimeOptions::default());
    runtime
        .evaluate_cel_expression_with_input(&expr.cel, bindings)
        .map_err(|_| SourceExecutionError::HttpJson)
}

fn eval_http_flow_bool(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<bool, SourceExecutionError> {
    match eval_http_json_value(expr, bindings)? {
        Value::Bool(value) => Ok(value),
        _ => Err(SourceExecutionError::HttpJson),
    }
}

async fn prepare_http_json_request(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    base_url: &str,
    path: &str,
) -> Result<PreparedHttpJsonRequest, SourceExecutionError> {
    let base = reqwest::Url::parse(base_url).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_allowed_base_url(source_id, source, &base)
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let url = append_http_json_path(&base, path).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_same_origin(&base, &url).map_err(|_| SourceExecutionError::HttpJson)?;
    let client = http_json_client_for(state, source_id, source, &base).await?;
    Ok(PreparedHttpJsonRequest { url, client })
}

async fn http_json_client_for(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    base: &reqwest::Url,
) -> Result<reqwest::Client, SourceExecutionError> {
    let cache_key = format!("{}|{}", source_id, base.as_str().trim_end_matches('/'));
    if let Some(client) = state
        .http_json_clients
        .lock()
        .await
        .get(&cache_key)
        .cloned()
    {
        return Ok(client);
    }

    let resolved_addrs = ensure_http_json_url_policy(base, source)
        .await
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let host = base
        .host_str()
        .ok_or(SourceExecutionError::HttpJson)?
        .to_string();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(state.config.limits.worker_timeout_ms))
        .resolve_to_addrs(&host, &resolved_addrs)
        .build()
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let mut clients = state.http_json_clients.lock().await;
    let client = clients.entry(cache_key).or_insert(client).clone();
    Ok(client)
}

fn append_http_json_path(base: &reqwest::Url, path: &str) -> Result<reqwest::Url, ()> {
    if path.starts_with("//") {
        return Err(());
    }
    let suffix = path.trim_start_matches('/');
    if suffix
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(());
    }
    let base_path = base.path().trim_end_matches('/');
    let combined_path = if base_path.is_empty() || base_path == "/" {
        format!("/{suffix}")
    } else if suffix.is_empty() {
        base_path.to_string()
    } else {
        format!("{base_path}/{suffix}")
    };
    let mut url = base.clone();
    url.set_path(&combined_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn ensure_allowed_base_url(
    source_id: &str,
    source: &SourceConfig,
    base_url: &reqwest::Url,
) -> Result<(), SidecarError> {
    let normalized = base_url.as_str().trim_end_matches('/');
    if source
        .allowed_base_urls
        .iter()
        .map(|allowed| allowed.trim_end_matches('/'))
        .any(|allowed| allowed == normalized)
    {
        Ok(())
    } else {
        Err(SidecarError::Config(format!(
            "source {source_id} http_json base_url is not in allowed_base_urls"
        )))
    }
}

fn ensure_same_origin(base: &reqwest::Url, url: &reqwest::Url) -> Result<(), ()> {
    if base.scheme() == url.scheme()
        && base.host_str() == url.host_str()
        && base.port_or_known_default() == url.port_or_known_default()
    {
        Ok(())
    } else {
        Err(())
    }
}

async fn ensure_http_json_url_policy(
    url: &reqwest::Url,
    source: &SourceConfig,
) -> Result<Vec<SocketAddr>, ()> {
    let Some(host) = url.host_str() else {
        return Err(());
    };
    let port = url.port_or_known_default().ok_or(())?;
    if url.scheme() != "https" {
        if url.scheme() != "http" {
            return Err(());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            ensure_ip_allowed(ip, source)?;
            if !ip.is_loopback() && !is_private_or_link_local_ip(ip) {
                return Err(());
            }
            return Ok(vec![SocketAddr::new(ip, port)]);
        } else if is_localhost_host(host) {
            if !source.allow_insecure_localhost {
                return Err(());
            }
        } else if !source.allow_insecure_private_network {
            return Err(());
        } else {
            // Resolve below and allow only private/link-local addresses for
            // plain HTTP service names.
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure_ip_allowed(ip, source)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if is_localhost_host(host) {
        if source.allow_insecure_localhost || source.allow_insecure_private_network {
            return Ok(vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)]);
        }
        return Err(());
    }
    let mut resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ())?;
    let mut addrs = Vec::new();
    for address in &mut resolved {
        let ip = canonical_ip(address.ip());
        ensure_ip_allowed(ip, source)?;
        if url.scheme() == "http" && !ip.is_loopback() && !is_private_or_link_local_ip(ip) {
            return Err(());
        }
        addrs.push(address);
    }
    if addrs.is_empty() {
        return Err(());
    }
    Ok(addrs)
}

fn ensure_ip_allowed(ip: IpAddr, source: &SourceConfig) -> Result<(), ()> {
    let ip = canonical_ip(ip);
    if is_cloud_metadata_ip(ip) {
        return Err(());
    }
    if ip.is_loopback() {
        return if source.allow_insecure_localhost || source.allow_insecure_private_network {
            Ok(())
        } else {
            Err(())
        };
    }
    if is_private_or_link_local_ip(ip) {
        return if source.allow_insecure_private_network {
            Ok(())
        } else {
            Err(())
        };
    }
    Ok(())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(_) => ip,
    }
}

fn is_localhost_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_cloud_metadata_ip(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    match ip {
        IpAddr::V4(ip) => ip.octets() == [169, 254, 169, 254],
        IpAddr::V6(ip) => {
            ip.octets()
                == [
                    0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54,
                ]
        }
    }
}

fn is_private_or_link_local_ip(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_unspecified(),
    }
}

fn load_credentials(config: &SidecarConfig) -> Result<BTreeMap<String, Value>, SidecarError> {
    let mut credentials = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.credential_env.trim().is_empty() {
            continue;
        }
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
                "query_values": {},
                "fields": smoke.fields,
                "limit": 1,
                "purpose": smoke.purpose,
                "correlation_id": "startup-smoke",
                "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
            });
            if let Some(query_values) = request
                .get_mut("query_values")
                .and_then(Value::as_object_mut)
            {
                query_values.insert(smoke.field.clone(), Value::String(smoke.value.clone()));
                for (key, value) in &smoke.query_values {
                    query_values.insert(key.clone(), Value::String(value.clone()));
                }
            }
            match execute_source_json(state, source_id, source, request).await {
                Ok(execution) => {
                    let response = execution.value;
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
                    last_reason = smoke_execution_error_reason(&error);
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

fn smoke_execution_error_reason(error: &SourceExecutionError) -> String {
    match error {
        SourceExecutionError::HttpJson
        | SourceExecutionError::HttpJsonBadRequest
        | SourceExecutionError::HttpJsonTimeout => "source adapter execution failed".to_string(),
    }
}

async fn healthz(State(_state): State<Arc<AppState>>) -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

async fn ready(State(state): State<Arc<AppState>>) -> Response {
    let mut body = json!({ "status": "ready" });
    if let Some(assurance) = &state.config.assurance {
        body["config_hash"] = json!(assurance.config_hash);
        body["expression_hashes_verified"] = json!(assurance.expression_hashes_verified);
        body["runtime_verified"] = json!(assurance.runtime_verified);
        body["smoke_verified"] = json!(assurance.smoke_verified);
    }
    (StatusCode::OK, Json(body)).into_response()
}

async fn assurance(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    match &state.config.assurance {
        Some(assurance) => (StatusCode::OK, Json(assurance)).into_response(),
        None => problem(
            StatusCode::NOT_FOUND,
            "governed sidecar assurance is not configured",
        ),
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let mut body = String::new();
    body.push_str("# TYPE registry_notary_openfn_sidecar_source_permits gauge\n");
    for (source_id, source) in &state.config.sources {
        let max_permits = source
            .limits
            .max_in_flight
            .unwrap_or(state.config.limits.max_workers);
        let available = state
            .source_limiters
            .get(source_id)
            .map(|limiter| limiter.available_permits())
            .unwrap_or(0);
        let in_flight = max_permits.saturating_sub(available);
        for (label, value) in [
            ("max", max_permits),
            ("available", available),
            ("in_flight", in_flight),
        ] {
            body.push_str(&format!(
                "registry_notary_openfn_sidecar_source_permits{{source_id=\"{}\",state=\"{}\"}} {}\n",
                escape_metric_label(source_id),
                label,
                value
            ));
        }
    }
    let client_counts = {
        let clients = state.http_json_clients.lock().await;
        let mut counts = BTreeMap::<String, usize>::new();
        for key in clients.keys() {
            if let Some((source_id, _)) = key.split_once('|') {
                *counts.entry(source_id.to_string()).or_default() += 1;
            }
        }
        counts
    };
    if !client_counts.is_empty() {
        body.push_str("# TYPE registry_notary_openfn_sidecar_http_json_clients gauge\n");
        for (source_id, count) in client_counts {
            body.push_str(&format!(
                "registry_notary_openfn_sidecar_http_json_clients{{source_id=\"{}\"}} {}\n",
                escape_metric_label(&source_id),
                count
            ));
        }
    }
    let metrics = state.metrics.lock().await;
    if !metrics.is_empty() {
        body.push_str("# TYPE registry_notary_openfn_sidecar_lookup_total counter\n");
        body.push_str("# TYPE registry_notary_openfn_sidecar_lookup_duration_ms_total counter\n");
        body.push_str("# TYPE registry_notary_openfn_sidecar_lookup_items_total counter\n");
    }
    for (key, value) in metrics.iter() {
        let labels = metric_labels(key);
        body.push_str(&format!(
            "registry_notary_openfn_sidecar_lookup_total{{{labels}}} {}\n",
            value.count
        ));
        body.push_str(&format!(
            "registry_notary_openfn_sidecar_lookup_duration_ms_total{{{labels}}} {}\n",
            value.duration_ms_total
        ));
        body.push_str(&format!(
            "registry_notary_openfn_sidecar_lookup_items_total{{{labels}}} {}\n",
            value.items_total
        ));
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

fn metric_labels(key: &MetricKey) -> String {
    let mut labels = vec![
        format!("source_id=\"{}\"", escape_metric_label(&key.source_id)),
        format!("outcome=\"{}\"", escape_metric_label(&key.outcome)),
    ];
    if let Some(engine) = &key.engine {
        labels.push(format!("engine=\"{}\"", escape_metric_label(engine)));
    }
    if let Some(step_id) = &key.step_id {
        labels.push(format!("step_id=\"{}\"", escape_metric_label(step_id)));
    }
    labels.join(",")
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

    let query = match validate_query(&state, source, raw_query.as_deref(), query) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let correlation_id = headers
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let request = json!({
        "source_id": source_id,
        "dataset": dataset,
        "entity": entity,
        "lookup": {
            "field": query.lookup_field,
            "value": query.lookup_value,
        },
        "query_values": query.query_values,
        "fields": query.fields,
        "limit": query.limit,
        "purpose": purpose,
        "correlation_id": correlation_id.clone(),
        "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
    });

    let _source_permit = match acquire_source_permit(&state, source_id, "source_saturated", 1).await
    {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    let source_execution = match execute_source_json(&state, source_id, source, request).await {
        Ok(execution) => execution,
        Err(SourceExecutionError::HttpJson) => {
            record_metric_with_items(&state, source_id, "source_error", started_at.elapsed(), 1)
                .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "source_error",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar lookup failed"
            );
            return problem(StatusCode::BAD_GATEWAY, "source adapter execution failed");
        }
        Err(SourceExecutionError::HttpJsonTimeout) => {
            record_metric_with_items(&state, source_id, "source_timeout", started_at.elapsed(), 1)
                .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "source_timeout",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar lookup timed out"
            );
            return problem_with_code(
                StatusCode::GATEWAY_TIMEOUT,
                "source timeout",
                "source.timeout",
            );
        }
        Err(SourceExecutionError::HttpJsonBadRequest) => {
            record_metric_with_items(&state, source_id, "source_error", started_at.elapsed(), 1)
                .await;
            return problem(StatusCode::BAD_REQUEST, "invalid source adapter request");
        }
    };

    let response = normalize_worker_response(source_execution.value, &query.fields, query.limit);
    let outcome = if response.status().is_success() {
        "success"
    } else {
        "source_error"
    };
    record_metric_with_items(&state, source_id, outcome, started_at.elapsed(), 1).await;
    info!(
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        source_id = source_id.as_str(),
        outcome,
        worker_id = source_execution.worker_id,
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
    let request = json!({
        "mode": "batch_match",
        "source_id": source_id,
        "dataset": dataset,
        "entity": entity,
        "query_signature": body.query_signature,
        "items": body.items,
        "batch": source.batch.clone(),
        "fields": body.fields,
        "purpose": purpose,
        "correlation_id": correlation_id.clone(),
        "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
    });

    let batch_item_count = body.items.len();
    let _source_permit = match acquire_source_permit(
        &state,
        source_id,
        "batch_source_saturated",
        batch_item_count,
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    let source_execution = match execute_source_json(&state, source_id, source, request).await {
        Ok(execution) => execution,
        Err(SourceExecutionError::HttpJson) => {
            record_metric_with_items(
                &state,
                source_id,
                "batch_source_error",
                started_at.elapsed(),
                batch_item_count,
            )
            .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "batch_source_error",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar batch match failed"
            );
            return problem(StatusCode::BAD_GATEWAY, "source adapter execution failed");
        }
        Err(SourceExecutionError::HttpJsonTimeout) => {
            record_metric_with_items(
                &state,
                source_id,
                "batch_source_timeout",
                started_at.elapsed(),
                batch_item_count,
            )
            .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "batch_source_timeout",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar batch match timed out"
            );
            return problem_with_code(
                StatusCode::GATEWAY_TIMEOUT,
                "source timeout",
                "source.timeout",
            );
        }
        Err(SourceExecutionError::HttpJsonBadRequest) => {
            record_metric_with_items(
                &state,
                source_id,
                "batch_source_error",
                started_at.elapsed(),
                batch_item_count,
            )
            .await;
            return problem(StatusCode::BAD_REQUEST, "invalid source adapter request");
        }
    };

    let response = normalize_batch_worker_response(
        source_execution.value,
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
    record_metric_with_items(
        &state,
        source_id,
        outcome,
        started_at.elapsed(),
        batch_item_count,
    )
    .await;
    info!(
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        source_id = source_id.as_str(),
        outcome,
        worker_id = source_execution.worker_id,
        status = response.status().as_u16(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "sidecar batch match completed"
    );
    response
}

async fn enforce_uri_limit(request: Request<Body>, next: Next) -> Response {
    if request
        .uri()
        .path_and_query()
        .map_or(0, |value| value.as_str().len())
        > MAX_URI_BYTES
    {
        return problem(
            StatusCode::URI_TOO_LONG,
            "request URI exceeds configured byte limit",
        );
    }
    next.run(request).await
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

async fn record_metric_with_items(
    state: &AppState,
    source_id: &str,
    outcome: &str,
    duration: Duration,
    items: usize,
) {
    record_metric_with_labels(state, source_id, outcome, duration, items, None, None).await;
}

async fn record_metric_with_labels(
    state: &AppState,
    source_id: &str,
    outcome: &str,
    duration: Duration,
    items: usize,
    engine: Option<&str>,
    step_id: Option<&str>,
) {
    let key = MetricKey {
        source_id: source_id.to_string(),
        outcome: outcome.to_string(),
        engine: engine.map(ToOwned::to_owned),
        step_id: step_id.map(ToOwned::to_owned),
    };
    let mut metrics = state.metrics.lock().await;
    let value = metrics.entry(key).or_default();
    value.count = value.count.saturating_add(1);
    value.duration_ms_total = value
        .duration_ms_total
        .saturating_add(duration.as_millis() as u64);
    value.items_total = value.items_total.saturating_add(items as u64);
}

async fn record_http_flow_metric(
    state: &AppState,
    source_id: &str,
    step_id: Option<&str>,
    outcome: &str,
    items: usize,
) {
    record_metric_with_labels(
        state,
        source_id,
        outcome,
        Duration::ZERO,
        items,
        Some("http_flow"),
        step_id,
    )
    .await;
}

async fn acquire_http_json_rate_or_error(state: &AppState, source_id: &str) -> Option<Value> {
    let runtime = state.source_runtime.get(source_id)?;
    if let Some(retry_after) = source_backoff_retry_after(runtime).await {
        record_metric_with_items(state, source_id, "source_backoff", Duration::ZERO, 1).await;
        return Some(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after
            }
        }));
    }
    let Some(rate_limiter) = &runtime.rate_limiter else {
        return None;
    };
    let mut bucket = rate_limiter.lock().await;
    if let Err(wait) = bucket.try_take(Instant::now()) {
        let retry_after = duration_retry_after_seconds(wait);
        drop(bucket);
        record_metric_with_items(state, source_id, "source_rate_limited", Duration::ZERO, 1).await;
        return Some(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after
            }
        }));
    }
    None
}

async fn source_backoff_retry_after(runtime: &SourceRuntimeState) -> Option<u64> {
    let now = Instant::now();
    let mut backoff = runtime.backoff_until.lock().await;
    let until = backoff.as_ref().copied()?;
    if until <= now {
        *backoff = None;
        None
    } else {
        Some(duration_retry_after_seconds(until.duration_since(now)))
    }
}

fn duration_retry_after_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
        .max(1)
}

async fn remember_source_backoff(state: &AppState, source_id: &str, response: &Value) {
    let Some(error) = response.get("error").and_then(Value::as_object) else {
        return;
    };
    if !matches!(
        error.get("code").and_then(Value::as_str),
        Some("target_rate_limit" | "source.target_rate_limit")
    ) {
        return;
    }
    let seconds = error
        .get("retry_after_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(state.config.limits.retry_after_seconds)
        .max(1);
    if let Some(runtime) = state.source_runtime.get(source_id) {
        *runtime.backoff_until.lock().await = Some(Instant::now() + Duration::from_secs(seconds));
    }
}

async fn remember_source_backoff_seconds(state: &AppState, source_id: &str, seconds: u64) {
    if let Some(runtime) = state.source_runtime.get(source_id) {
        *runtime.backoff_until.lock().await =
            Some(Instant::now() + Duration::from_secs(seconds.max(1)));
    }
}

async fn acquire_source_permit(
    state: &Arc<AppState>,
    source_id: &str,
    saturated_outcome: &'static str,
    items: usize,
) -> Result<OwnedSemaphorePermit, Box<Response>> {
    let Some(limiter) = state.source_limiters.get(source_id) else {
        return Err(Box::new(problem(
            StatusCode::BAD_GATEWAY,
            "source limiter unavailable",
        )));
    };
    match limiter.clone().try_acquire_owned() {
        Ok(permit) => Ok(permit),
        Err(_) => {
            record_metric_with_items(state, source_id, saturated_outcome, Duration::ZERO, items)
                .await;
            let mut response = problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "source concurrency limit reached",
                "source.saturated",
            );
            if let Ok(value) =
                HeaderValue::from_str(&state.config.limits.retry_after_seconds.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            Err(Box::new(response))
        }
    }
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
    query_values: BTreeMap<String, String>,
    fields: Vec<String>,
    limit: usize,
}

fn validate_query(
    state: &AppState,
    source: &SourceConfig,
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
    if lookup_pairs.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "at least one lookup predicate is required",
        )));
    }
    if source.engine != SourceEngine::Fhir && lookup_pairs.len() != 1 {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "exactly one lookup predicate is required",
        )));
    }
    let query_values = lookup_pairs.into_iter().collect::<BTreeMap<_, _>>();
    let (lookup_field, lookup_value, query_values) =
        primary_lookup_value(source, &query_values).expect("at least one lookup pair");
    if lookup_value.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "lookup predicate value is required",
        )));
    }

    Ok(LookupQuery {
        lookup_field,
        lookup_value,
        query_values,
        fields,
        limit,
    })
}

fn primary_lookup_value(
    source: &SourceConfig,
    query_values: &BTreeMap<String, String>,
) -> Option<(String, String, BTreeMap<String, String>)> {
    if source.engine == SourceEngine::Fhir {
        if let Some(smoke) = &source.smoke_lookup {
            if let Some(value) = query_values.get(&smoke.field) {
                return Some((smoke.field.clone(), value.clone(), query_values.clone()));
            }
        }
    }
    query_values
        .iter()
        .next()
        .map(|(field, value)| (field.clone(), value.clone(), query_values.clone()))
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
        Some("target_auth" | "source.target_auth") => json!({ "code": "target_auth" }),
        Some("target_rate_limit" | "source.target_rate_limit") => {
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
        Some("target_rate_limit" | "source.target_rate_limit") => {
            let mut response = problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "target rate limited",
                "source.target_rate_limit",
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
        Some("target_auth" | "source.target_auth") => problem_with_code(
            StatusCode::BAD_GATEWAY,
            "target auth failed",
            "source.target_auth",
        ),
        Some("source.timeout") => problem_with_code(
            StatusCode::GATEWAY_TIMEOUT,
            "source timeout",
            "source.timeout",
        ),
        Some("source.unavailable" | "source_unavailable") => problem_with_code(
            StatusCode::BAD_GATEWAY,
            "source unavailable",
            "source.unavailable",
        ),
        _ => problem_with_code(
            StatusCode::BAD_GATEWAY,
            "source adapter execution failed",
            "source.unavailable",
        ),
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

const MAX_URI_BYTES: usize = 8 * 1024;
const DEFAULT_SOURCE_CACHE_MAX_ENTRIES: usize = 10_000;

fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_request_body_timeout_ms() -> u64 {
    10_000
}

fn default_http1_header_read_timeout_ms() -> u64 {
    10_000
}

fn default_max_connections() -> usize {
    1024
}

fn default_smoke_purpose() -> String {
    "startup-readiness-smoke".to_string()
}

fn default_fhir_version() -> String {
    "R4".to_string()
}

fn default_fhir_search_method() -> String {
    "get".to_string()
}

fn default_fhir_prefer_handling() -> String {
    "strict".to_string()
}

fn default_fhir_accept() -> String {
    "application/fhir+json".to_string()
}

const fn default_true() -> bool {
    true
}

const fn default_fhir_max_search_results() -> usize {
    2
}

const fn default_fhir_max_source_bundle_bytes() -> usize {
    5 * 1024 * 1024
}

fn default_fhir_cardinality_one() -> String {
    "one".to_string()
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> SidecarConfig {
        SidecarConfig {
            server: ServerConfig {
                bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                request_timeout_ms: default_request_timeout_ms(),
                request_body_timeout_ms: default_request_body_timeout_ms(),
                http1_header_read_timeout_ms: default_http1_header_read_timeout_ms(),
                max_connections: default_max_connections(),
            },
            auth: AuthConfig {
                bearer_tokens: vec![BearerTokenConfig {
                    id: "notary".to_string(),
                    token: None,
                    hash_env: Some("TEST_OPENFN_SIDECAR_TOKEN_HASH".to_string()),
                }],
            },
            config_trust: None,
            limits: LimitConfig {
                max_workers: 1,
                worker_timeout_ms: 1_000,
                max_output_bytes: 1_024,
                max_request_bytes: 1_024,
                max_query_parameter_bytes: 1_024,
                liveness_window_ms: default_liveness_window_ms(),
                retry_after_seconds: default_retry_after_seconds(),
                max_batch_items: default_max_batch_items(),
                batch_timeout_ms: None,
                max_worker_memory_mb: None,
            },
            sources: BTreeMap::from([(
                "people".to_string(),
                SourceConfig {
                    dataset: "civil_registry".to_string(),
                    entity: "person".to_string(),
                    engine: SourceEngine::HttpJson,
                    credential_env: "TEST_HTTP_JSON_SOURCE_CREDENTIAL".to_string(),
                    credential_public_fields: vec!["baseUrl".to_string()],
                    batch: SourceBatchConfig::default(),
                    limits: SourceRuntimeLimitConfig::default(),
                    allowed_base_urls: vec!["https://source.example.test".to_string()],
                    allow_insecure_localhost: false,
                    allow_insecure_private_network: false,
                    http_json: Some(HttpJsonSourceConfig {
                        method: HttpJsonMethod::Get,
                        base_url: HttpJsonCelExpression {
                            cel: "credential_public.baseUrl".to_string(),
                        },
                        path: "/records".to_string(),
                        query: BTreeMap::new(),
                        headers: BTreeMap::new(),
                        auth: None,
                        response: HttpJsonResponseConfig {
                            records: HttpJsonCelExpression {
                                cel: "body.results".to_string(),
                            },
                        },
                        batch: None,
                    }),
                    http_flow: None,
                    fhir: None,
                    cache: None,
                    smoke_lookup: Some(SmokeLookupConfig {
                        field: "national_id".to_string(),
                        value: "person-1".to_string(),
                        query_values: BTreeMap::new(),
                        fields: vec!["national_id".to_string()],
                        purpose: default_smoke_purpose(),
                    }),
                },
            )]),
            assurance: None,
            governed_acceptance: None,
        }
    }

    fn minimal_http_json_config() -> SidecarConfig {
        minimal_config()
    }

    #[test]
    fn server_limits_must_be_nonzero() {
        type MutateConfig = fn(&mut SidecarConfig);
        let cases: [(&str, MutateConfig); 4] = [
            ("server.request_timeout_ms", |config: &mut SidecarConfig| {
                config.server.request_timeout_ms = 0
            }),
            (
                "server.request_body_timeout_ms",
                |config: &mut SidecarConfig| config.server.request_body_timeout_ms = 0,
            ),
            (
                "server.http1_header_read_timeout_ms",
                |config: &mut SidecarConfig| config.server.http1_header_read_timeout_ms = 0,
            ),
            ("server.max_connections", |config: &mut SidecarConfig| {
                config.server.max_connections = 0
            }),
        ];
        for (label, mutate) in cases {
            let mut config = minimal_config();
            mutate(&mut config);
            let error =
                validate_config(&config).expect_err("zero sidecar server limit is rejected");
            assert!(
                error.to_string().contains(label),
                "expected {label} in {error}"
            );
        }
    }

    #[test]
    fn batch_timeout_limit_must_be_nonzero_when_configured() {
        let mut config = minimal_config();
        config.limits.batch_timeout_ms = Some(0);

        let error = validate_config(&config).expect_err("zero batch timeout is rejected");

        assert!(
            error.to_string().contains("limits.batch_timeout_ms"),
            "expected batch timeout limit in {error}"
        );
    }

    #[test]
    fn source_concurrency_limit_must_be_nonzero() {
        let mut config = minimal_http_json_config();
        config
            .sources
            .get_mut("people")
            .expect("source exists")
            .limits
            .max_in_flight = Some(0);

        let error =
            validate_config(&config).expect_err("zero source concurrency limit is rejected");

        assert!(
            error.to_string().contains("limits.max_in_flight"),
            "expected source limit in {error}"
        );
    }

    #[test]
    fn source_rate_limit_config_must_be_consistent() {
        type MutateSource = fn(&mut SourceConfig);
        let cases: [(&str, MutateSource); 3] = [
            ("limits.requests_per_second", |source| {
                source.limits.requests_per_second = Some(0)
            }),
            ("limits.burst", |source| source.limits.burst = Some(0)),
            ("limits.burst requires", |source| {
                source.limits.burst = Some(5)
            }),
        ];
        for (label, mutate) in cases {
            let mut config = minimal_config();
            mutate(config.sources.get_mut("people").expect("source exists"));

            let error = validate_config(&config).expect_err("invalid source rate limit rejected");

            assert!(
                error.to_string().contains(label),
                "expected {label} in {error}"
            );
        }
    }

    #[test]
    fn source_batch_and_cache_config_must_be_consistent() {
        let mut config = minimal_http_json_config();
        config
            .sources
            .get_mut("people")
            .expect("source exists")
            .batch
            .max_parallel = Some(2);
        let error = validate_config(&config).expect_err("max_parallel without mode is rejected");
        assert!(error.to_string().contains("batch.max_parallel"));

        let mut config = minimal_config();
        let source = config.sources.get_mut("people").expect("source exists");
        source.cache = Some(SourceCacheConfig {
            exact_match_ttl_ms: None,
            not_found_ttl_ms: None,
            max_entries: None,
        });
        let error = validate_config(&config).expect_err("empty cache config is rejected");
        assert!(error.to_string().contains("cache"));

        let mut config = minimal_http_json_config();
        let source = config.sources.get_mut("people").expect("source exists");
        source.cache = Some(SourceCacheConfig {
            exact_match_ttl_ms: Some(60_000),
            not_found_ttl_ms: None,
            max_entries: Some(0),
        });
        let error = validate_config(&config).expect_err("zero cache cap is rejected");
        assert!(error.to_string().contains("cache.max_entries"));
    }

    #[test]
    fn http_json_native_batch_requires_batch_mapping() {
        let mut config = minimal_http_json_config();
        config
            .sources
            .get_mut("people")
            .expect("source exists")
            .batch
            .mode = SourceBatchMode::NativeBatch;

        let error = validate_config(&config).expect_err("native batch mapping is required");

        assert!(error.to_string().contains("http_json.batch"));
    }

    #[test]
    fn http_json_ip_policy_blocks_private_and_metadata_by_default() {
        let mut source = minimal_config()
            .sources
            .remove("people")
            .expect("source exists");
        source.engine = SourceEngine::HttpJson;
        source.allow_insecure_localhost = false;
        source.allow_insecure_private_network = false;

        assert!(ensure_ip_allowed("10.0.0.1".parse().unwrap(), &source).is_err());

        source.allow_insecure_private_network = true;
        assert!(ensure_ip_allowed("10.0.0.1".parse().unwrap(), &source).is_ok());
        assert!(ensure_ip_allowed("169.254.169.254".parse().unwrap(), &source).is_err());
        assert!(ensure_ip_allowed("fd00:ec2::254".parse().unwrap(), &source).is_err());
        assert!(ensure_ip_allowed("::ffff:169.254.169.254".parse().unwrap(), &source).is_err());

        source.allow_insecure_private_network = false;
        assert!(ensure_ip_allowed("::ffff:10.0.0.1".parse().unwrap(), &source).is_err());
        source.allow_insecure_localhost = true;
        assert!(ensure_ip_allowed("127.0.0.1".parse().unwrap(), &source).is_ok());
    }

    #[tokio::test]
    async fn http_json_url_policy_rejects_plain_http_public_hosts_even_with_private_network_escape()
    {
        let mut source = minimal_config()
            .sources
            .remove("people")
            .expect("source exists");
        source.engine = SourceEngine::HttpJson;
        source.allow_insecure_localhost = true;
        source.allow_insecure_private_network = true;

        let public_http = reqwest::Url::parse("http://example.com").expect("url parses");
        assert!(ensure_http_json_url_policy(&public_http, &source)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn http_json_url_policy_rejects_plain_http_public_ip_literals_even_with_private_network_escape(
    ) {
        let mut source = minimal_config()
            .sources
            .remove("people")
            .expect("source exists");
        source.engine = SourceEngine::HttpJson;
        source.allow_insecure_localhost = true;
        source.allow_insecure_private_network = true;

        let public_http = reqwest::Url::parse("http://93.184.216.34").expect("url parses");
        assert!(ensure_http_json_url_policy(&public_http, &source)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn http_json_url_policy_keeps_metadata_blocked_with_private_network_escape() {
        let mut source = minimal_config()
            .sources
            .remove("people")
            .expect("source exists");
        source.engine = SourceEngine::HttpJson;
        source.allow_insecure_private_network = true;

        let metadata_http = reqwest::Url::parse("http://169.254.169.254").expect("url parses");
        assert!(ensure_http_json_url_policy(&metadata_http, &source)
            .await
            .is_err());
        let metadata_ipv6_http = reqwest::Url::parse("http://[fd00:ec2::254]").expect("url parses");
        assert!(ensure_http_json_url_policy(&metadata_ipv6_http, &source)
            .await
            .is_err());
        let metadata_mapped_http =
            reqwest::Url::parse("http://[::ffff:169.254.169.254]").expect("url parses");
        assert!(ensure_http_json_url_policy(&metadata_mapped_http, &source)
            .await
            .is_err());
    }

    #[test]
    fn fhir_base_url_policy_allows_private_network_http_service_names_only_with_escape() {
        let mut source = minimal_config()
            .sources
            .remove("people")
            .expect("source exists");
        source.engine = SourceEngine::Fhir;
        source.allow_insecure_localhost = false;
        source.allow_insecure_private_network = false;

        let docker_service =
            reqwest::Url::parse("http://fhir-fixture-server:8080/fhir").expect("url parses");
        assert!(validate_fhir_base_url_policy("fhir", &source, &docker_service).is_err());

        source.allow_insecure_private_network = true;
        validate_fhir_base_url_policy("fhir", &source, &docker_service)
            .expect("private network escape allows docker service names");

        let metadata =
            reqwest::Url::parse("http://metadata.google.internal/fhir").expect("url parses");
        assert!(validate_fhir_base_url_policy("fhir", &source, &metadata).is_err());
    }
}
