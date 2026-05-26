use crate::{WorkerCommand, WorkerError, WorkerPool, WorkerPoolConfig};
use axum::{
    extract::{Path, Query, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use registry_platform_authcommon::{parse_bearer_token, parse_fingerprint, verify_api_key};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    fmt,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Clone, Debug, Deserialize)]
pub struct SidecarConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub limits: LimitConfig,
    pub openfn: OpenFnConfig,
    pub worker: WorkerProcessConfig,
    pub sources: BTreeMap<String, SourceConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    pub bearer_tokens: Vec<BearerTokenConfig>,
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

#[derive(Clone, Debug, Deserialize)]
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
    pub max_worker_memory_mb: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenFnConfig {
    pub cli_build_tool: String,
    pub runtime: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WorkerProcessConfig {
    pub command: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub version_args: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SourceConfig {
    pub dataset: String,
    pub entity: String,
    #[serde(default)]
    pub job: Option<PathBuf>,
    #[serde(default)]
    pub adaptor: Option<String>,
    #[serde(default)]
    pub workflow: Option<SourceWorkflowConfig>,
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
    pub job: PathBuf,
    pub adaptor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<SourceWorkflowNextConfig>,
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

#[derive(Clone, Debug, Deserialize)]
pub struct SmokeLookupConfig {
    pub field: String,
    pub value: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default = "default_smoke_purpose")]
    pub purpose: String,
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
        max_workers: config.limits.max_workers,
        request_timeout: Duration::from_millis(config.limits.worker_timeout_ms),
        max_request_bytes: config.limits.max_request_bytes,
        max_stdout_bytes: config.limits.max_output_bytes,
        max_stderr_bytes: config.limits.max_output_bytes,
        max_memory_bytes: config
            .limits
            .max_worker_memory_mb
            .map(|megabytes| megabytes.saturating_mul(1024 * 1024)),
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

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/datasets/{dataset}/{entity}", get(lookup))
        .with_state(state))
}

pub async fn run(config: SidecarConfig) -> Result<(), Box<dyn std::error::Error>> {
    let bind = config.server.bind;
    let app = sidecar_router(config).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
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
    match (&source.job, &source.adaptor, &source.workflow) {
        (Some(job), Some(adaptor), None) => {
            validate_source_job(source_id, "job", job)?;
            validate_source_adaptor(source_id, "adaptor", adaptor)?;
        }
        (None, None, Some(workflow)) => validate_source_workflow(source_id, workflow)?,
        _ => {
            return Err(SidecarError::Config(format!(
                "source {source_id} must configure either job/adaptor or workflow.steps"
            )));
        }
    }
    Ok(())
}

fn validate_source_workflow(
    source_id: &str,
    workflow: &SourceWorkflowConfig,
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
        validate_source_job(
            source_id,
            &format!("workflow step {} job", step.id),
            &step.job,
        )?;
        validate_source_adaptor(
            source_id,
            &format!("workflow step {} adaptor", step.id),
            &step.adaptor,
        )?;
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
            "source {source_id} workflow step {step_id} has multiple input steps, which is not supported by the pinned OpenFn runtime"
        )));
    }
    let mut visited = BTreeSet::new();
    for start_step in &workflow.steps {
        if visited.contains(start_step.id.as_str()) {
            continue;
        }
        let mut path = BTreeSet::new();
        let current = start_step.id.as_str();
        if !path.insert(current) {
            return Err(SidecarError::Config(format!(
                "source {source_id} workflow contains a cycle at step {current}"
            )));
        }
        if let Some(next_steps) = next_by_step.get(current) {
            for next in next_steps {
                detect_workflow_cycle(source_id, &next_by_step, next, &mut path, &visited)?;
            }
        }
        visited.extend(path);
    }

    Ok(())
}

fn detect_workflow_cycle<'a>(
    source_id: &str,
    next_by_step: &BTreeMap<&'a str, Vec<&'a str>>,
    current: &'a str,
    path: &mut BTreeSet<&'a str>,
    visited: &BTreeSet<&'a str>,
) -> Result<(), SidecarError> {
    if visited.contains(current) {
        return Ok(());
    }
    if !path.insert(current) {
        return Err(SidecarError::Config(format!(
            "source {source_id} workflow contains a cycle at step {current}"
        )));
    }
    if let Some(next_steps) = next_by_step.get(current) {
        for next in next_steps {
            detect_workflow_cycle(source_id, next_by_step, next, path, visited)?;
        }
    }
    Ok(())
}

fn validate_source_job(source_id: &str, label: &str, job: &FsPath) -> Result<(), SidecarError> {
    if !job.is_file() {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} {} is missing",
            job.display()
        )));
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
            "source {source_id} {label} must include a version pin"
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
    if let Some(workflow) = &source.workflow {
        workflow
            .steps
            .iter()
            .map(|step| step.adaptor.as_str())
            .collect()
    } else {
        source.adaptor.as_deref().into_iter().collect()
    }
}

fn add_source_execution(request: &mut Value, source: &SourceConfig) {
    let Some(object) = request.as_object_mut() else {
        return;
    };
    if let Some(workflow) = &source.workflow {
        object.insert("workflow".to_string(), json!(workflow));
    } else {
        object.insert(
            "job".to_string(),
            json!(source.job.as_ref().expect("source job is validated")),
        );
        object.insert(
            "adaptor".to_string(),
            json!(source
                .adaptor
                .as_ref()
                .expect("source adaptor is validated")),
        );
    }
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
        add_source_execution(&mut request, source);
        let response =
            state
                .pool
                .execute_json(request)
                .await
                .map_err(|error| SidecarError::SmokeLookup {
                    source_id: source_id.clone(),
                    reason: smoke_error_reason(&error),
                })?;
        let Some(records) = response.get("data").and_then(Value::as_array) else {
            return Err(SidecarError::SmokeLookup {
                source_id: source_id.clone(),
                reason: "worker response did not contain data array".to_string(),
            });
        };
        if !records.iter().any(|record| {
            record
                .get(&smoke.field)
                .and_then(Value::as_str)
                .is_some_and(|value| value == smoke.value)
        }) {
            return Err(SidecarError::SmokeLookup {
                source_id: source_id.clone(),
                reason: format!(
                    "worker response did not contain expected smoke record for {}",
                    smoke.field
                ),
            });
        };
    }
    Ok(())
}

fn smoke_error_reason(error: &WorkerError) -> String {
    match error {
        WorkerError::Saturated { .. } => "worker pool saturated".to_string(),
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
    let snapshot = state.pool.snapshot().await;
    if snapshot.idle_workers + snapshot.in_flight == snapshot.max_workers {
        (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
    } else {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "worker pool is not fully available",
        )
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let snapshot = state.pool.snapshot().await;
    let mut body = format!(
        concat!(
            "# TYPE registry_witness_openfn_sidecar_workers gauge\n",
            "registry_witness_openfn_sidecar_workers{{state=\"max\"}} {}\n",
            "registry_witness_openfn_sidecar_workers{{state=\"idle\"}} {}\n",
            "registry_witness_openfn_sidecar_workers{{state=\"in_flight\"}} {}\n",
            "# TYPE registry_witness_openfn_sidecar_worker_completions_total counter\n",
            "registry_witness_openfn_sidecar_worker_completions_total {}\n"
        ),
        snapshot.max_workers, snapshot.idle_workers, snapshot.in_flight, snapshot.completed_total
    );
    let metrics = state.metrics.lock().await;
    if !metrics.is_empty() {
        body.push_str("# TYPE registry_witness_openfn_sidecar_lookup_total counter\n");
        body.push_str("# TYPE registry_witness_openfn_sidecar_lookup_duration_ms_total counter\n");
    }
    for (key, value) in metrics.iter() {
        body.push_str(&format!(
            "registry_witness_openfn_sidecar_lookup_total{{source_id=\"{}\",outcome=\"{}\"}} {}\n",
            escape_metric_label(&key.source_id),
            escape_metric_label(&key.outcome),
            value.count
        ));
        body.push_str(&format!(
            "registry_witness_openfn_sidecar_lookup_duration_ms_total{{source_id=\"{}\",outcome=\"{}\"}} {}\n",
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
    add_source_execution(&mut request, source);

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
