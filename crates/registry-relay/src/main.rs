// SPDX-License-Identifier: Apache-2.0
//! registry-relay binary entry point.
//!
//! Wires the V1 gateway into a runnable HTTP server:
//! 1. Initialise operational tracing on stderr.
//! 2. Load and validate the YAML config from `--config <path>`, the
//!    `REGISTRY_RELAY_CONFIG` env var, or `./config/example.yaml` (in that
//!    order of precedence).
//! 3. Build the auth provider from the configured credential references.
//!    The active provider is stored in the runtime snapshot so governed
//!    compatible credential changes can swap it without a process restart.
//! 4. Build the configured audit sink: stdout, file, or syslog, with
//!    platform audit envelopes.
//! 5. Build ingest, readiness, entity registry, row-query, and aggregate
//!    query state, then compose the public data-plane router.
//! 6. Bind on `config.server.bind`, optionally bind the admin router on
//!    `config.server.admin_bind`, serve, and shut down cleanly on
//!    `SIGINT`/`Ctrl-C` or `SIGTERM`.
//!
//! ## Error handling
//!
//! `main` propagates failures as [`crate::error::Error`]. The error
//! taxonomy already covers config parsing and binding failures; the
//! process exit code is non-zero on any error and the failing line is
//! also emitted via `tracing::error!` so operators can correlate.

use std::collections::BTreeMap;
use std::env;
use std::error::Error as StdError;
use std::fmt as std_fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use datafusion::execution::context::SessionContext;
use registry_config_report::{
    redact_config_value, ConfigValueClassification, LiveApplyClass, ReportStatus, RequiredEnvStatus,
};
use registry_platform_audit::AuditChainProfile;
use registry_platform_authcommon::{fingerprint_api_key, CredentialFingerprintProvider};
use registry_platform_config::{expand_config_env_vars, verify_config_bundle, ConfigBundleError};
use registry_platform_ops::{
    internal_config_hash, override_pin_active_and_unexpired, AntiRollbackKey, ConfigOverrideMode,
    ConfigSource, DeploymentProfile, FileAntiRollbackStore,
};
use registry_relay::audit::{
    AuditPipeline, ConfigAuditExt, FileSink, OperationalAuditEvent, StdoutSink, SyslogSink,
};
use registry_relay::auth::middleware::{AuthProviderRef, RuntimeAuthProvider};
use registry_relay::auth::runtime::build_auth;
use registry_relay::config::governed::parse_candidate_config_with_provenance;
use registry_relay::config::{
    self, AuditSinkConfig, Config, IssuerConfig, SignerConfig, SourceConfig,
};
use registry_relay::entity::EntityRegistry;
use registry_relay::error::{ConfigError, Error};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot};
use registry_relay::observability::RequestMetrics;
use registry_relay::provenance::{
    build_resolved_provenance_config, publicschema::build_publicschema_registry, ProvenanceState,
    ResolvedProvenanceConfig,
};
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
use registry_relay::runtime_config::{RelayRuntimeHandle, RelayRuntimeSnapshot};
use registry_relay::serve::{serve_listener, ServeLimits};
#[cfg(feature = "spdci-api-standards")]
use registry_relay::spdci::build_spdci_response_mapper;
use serde::Serialize;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use ulid::Ulid;

/// CLI flag for the config path. Kept minimal: a single `--config
/// <path>` positional plus the `REGISTRY_RELAY_CONFIG` env var fallback.
const CONFIG_FLAG: &str = "--config";
const ENV_FILE_FLAG: &str = "--env-file";
const BIND_FLAG: &str = "--bind";
const ID_FLAG: &str = "--id";

/// Top-level command for shell-free container liveness probing.
const HEALTHCHECK_COMMAND: &str = "healthcheck";

/// Generates a standalone API key and canonical fingerprint.
const GENERATE_API_KEY_COMMAND: &str = "generate-api-key";

/// Top-level command for generating the OpenAPI release artifact.
const OPENAPI_COMMAND: &str = "openapi";

/// Offline operator diagnostics for config, env, and metadata readiness.
const DOCTOR_COMMAND: &str = "doctor";

/// Prints a redacted resolved configuration explanation.
const EXPLAIN_CONFIG_COMMAND: &str = "explain-config";

/// Prints a lightweight JSON schema for top-level config discovery.
const SCHEMA_COMMAND: &str = "schema";

/// Top-level namespace for operator configuration commands.
const CONFIG_COMMAND: &str = "config";

/// Audit operator tooling command and its offline chain-recovery subcommand.
const AUDIT_COMMAND: &str = "audit";
const QUARANTINE_SUBCOMMAND: &str = "quarantine";
const REASON_FLAG: &str = "--reason";
const OPERATOR_FLAG: &str = "--operator";

/// Verifies a signed governed-config target without applying it.
const VERIFY_BUNDLE_COMMAND: &str = "verify-bundle";
const APPLY_BUNDLE_COMMAND: &str = "apply-bundle";

/// Healthcheck target override flag.
const HEALTHCHECK_URL_FLAG: &str = "--url";

/// Healthcheck request timeout override flag.
const HEALTHCHECK_TIMEOUT_FLAG: &str = "--timeout-ms";

/// Default healthcheck endpoint inside the container.
const DEFAULT_HEALTHCHECK_URL: &str = "http://127.0.0.1:8080/healthz";

/// Default healthcheck timeout in milliseconds.
const DEFAULT_HEALTHCHECK_TIMEOUT_MS: u64 = 5_000;

/// Last-resort default config path.
const DEFAULT_CONFIG_PATH: &str = "./config/example.yaml";

const BUNDLE_DIR_FLAG: &str = "--bundle-dir";
const ANCHOR_PATH_FLAG: &str = "--anchor-path";
const STATE_PATH_FLAG: &str = "--state-path";
const FORMAT_FLAG: &str = "--format";
const PROFILE_FLAG: &str = "--profile";
const INITIALIZE_STATE_FLAG: &str = "--initialize-state";
const RELAY_CONFIG_SCHEMA_VERSION: &str = "registry.relay.config.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Version,
    Serve {
        config_path: PathBuf,
        env_file: Option<PathBuf>,
        bind_override: Option<SocketAddr>,
        initialize_state: bool,
    },
    Healthcheck {
        url: String,
        timeout: Duration,
    },
    GenerateApiKey(GenerateApiKeyCommand),
    Openapi {
        config_path: PathBuf,
        env_file: Option<PathBuf>,
    },
    Doctor {
        config_path: PathBuf,
        env_file: Option<PathBuf>,
        format: OutputFormat,
        profile_override: Option<DeploymentProfile>,
    },
    ExplainConfig {
        config_path: PathBuf,
        env_file: Option<PathBuf>,
        format: OutputFormat,
    },
    Schema {
        format: OutputFormat,
    },
    ConfigVerifyBundle(ConfigVerifyBundleCommand),
    AuditQuarantine {
        config_path: PathBuf,
        env_file: Option<PathBuf>,
        reason: String,
        operator: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GenerateApiKeyCommand {
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigVerifyBundleCommand {
    bundle_dir: PathBuf,
    anchor_path: PathBuf,
    state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliError(String);

impl std_fmt::Display for CliError {
    fn fmt(&self, f: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for CliError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationalLogFormat {
    Text,
    Json,
}

impl OperationalLogFormat {
    fn from_env() -> Self {
        env::var("REGISTRY_RELAY_LOG_FORMAT")
            .map(|value| Self::parse(&value))
            .unwrap_or(Self::Text)
    }

    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" | "jsonl" => Self::Json,
            _ => Self::Text,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // The error itself has already been logged at the failing
            // site (config loader logs operator context; bind/serve
            // failures are logged here). The exit code is the only
            // surface left.
            error!(error = %err, "registry-relay exiting with failure");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match parse_cli_command_from(env::args().collect())? {
        CliCommand::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::Serve {
            config_path,
            env_file,
            bind_override,
            initialize_state,
        } => run_server(config_path, env_file, bind_override, initialize_state).await,
        CliCommand::Healthcheck { url, timeout } => {
            run_healthcheck(&url, timeout).await?;
            println!("registry-relay healthcheck ok");
            Ok(())
        }
        CliCommand::GenerateApiKey(command) => {
            println!("{}", generate_api_key_output(&command.id)?);
            Ok(())
        }
        CliCommand::Openapi {
            config_path,
            env_file,
        } => run_openapi(config_path, env_file).await,
        CliCommand::Doctor {
            config_path,
            env_file,
            format,
            profile_override,
        } => run_doctor(config_path, env_file, format, profile_override).await,
        CliCommand::ExplainConfig {
            config_path,
            env_file,
            format,
        } => run_explain_config(config_path, env_file, format).await,
        CliCommand::Schema { format } => run_schema(format).await,
        CliCommand::ConfigVerifyBundle(command) => run_config_verify_bundle(command).await,
        CliCommand::AuditQuarantine {
            config_path,
            env_file,
            reason,
            operator,
        } => run_audit_quarantine(config_path, env_file, reason, operator).await,
    }
}

async fn run_server(
    config_path: PathBuf,
    env_file: Option<PathBuf>,
    bind_override: Option<SocketAddr>,
    initialize_state: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    load_env_file_arg(env_file.as_deref())?;
    let handle = Arc::new(RelayRuntimeHandle::new(
        compile_relay_runtime_with_options(
            config_path,
            bind_override,
            config::LoadOptions { initialize_state },
        )
        .await?,
    ));
    let runtime = handle.load_full();
    let app = build_relay_app_from_runtime(Arc::clone(&handle))?;

    runtime
        .ingest
        .run_initial_ingest(runtime.readiness_tx.clone())
        .await;
    let (mut refresh_tasks, refresh_shutdown) = Arc::clone(&runtime.ingest)
        .spawn_refresh_tasks_with_config(
            &runtime.config,
            runtime.readiness_tx.clone(),
            Arc::clone(&runtime.audit_sink),
        );

    let provenance_state_for_log = runtime.provenance_state.as_ref().map(|state| {
        let cfg = state.config();
        (state.is_enabled(), cfg.mode, cfg.issuer_did.clone())
    });

    let listener = TcpListener::bind(runtime.bind).await.map_err(|err| {
        error!(error = %err, bind = %runtime.bind, "failed to bind listener");
        err
    })?;

    match provenance_state_for_log.as_ref() {
        Some((enabled, mode, issuer_did)) => {
            info!(
                bind = %runtime.bind,
                admin_bind = ?runtime.admin_bind,
                datasets = runtime.dataset_count(),
                api_keys = runtime.auth_size_hint(),
                audit_sink = runtime.audit_kind,
                provenance_enabled = *enabled,
                provenance_mode = ?mode,
                provenance_issuer_did = %issuer_did,
                "registry-relay listening"
            );
        }
        None => {
            info!(
                bind = %runtime.bind,
                admin_bind = ?runtime.admin_bind,
                datasets = runtime.dataset_count(),
                api_keys = runtime.auth_size_hint(),
                audit_sink = runtime.audit_kind,
                provenance_enabled = false,
                "registry-relay listening"
            );
        }
    }

    let admin_listener = match runtime.admin_bind {
        Some(addr) => Some(TcpListener::bind(addr).await.map_err(|err| {
            error!(error = %err, bind = %addr, "failed to bind admin listener");
            err
        })?),
        None => None,
    };

    let serve_limits = ServeLimits::from_config(&runtime.config.server);
    let main_serve = serve_listener(listener, app, serve_limits, shutdown_signal());

    // Run both servers concurrently. `tokio::select!` is the natural
    // fit because either listener exiting (clean or not) tears down
    // the other.
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        if let Some(admin_listener) = admin_listener {
            let auth: AuthProviderRef = Arc::new(RuntimeAuthProvider::new(Arc::clone(&handle)));
            let admin_app = registry_relay::server::build_admin_app_with_metadata_and_metrics(
                Arc::clone(&runtime.config),
                auth,
                Arc::clone(&runtime.audit_sink),
                runtime.readiness_rx.clone(),
                runtime.readiness_tx.clone(),
                Arc::clone(&runtime.ingest),
                runtime.compiled_metadata.clone(),
                Arc::clone(&runtime.metrics),
            )?
            .layer(Extension(Arc::clone(&handle)));
            let admin_serve =
                serve_listener(admin_listener, admin_app, serve_limits, shutdown_signal());
            tokio::select! {
                r = main_serve => r.map_err(Into::into),
                r = admin_serve => r.map_err(Into::into),
            }
        } else {
            main_serve.await.map_err(Into::into)
        };

    // Best-effort audit flush on the way out, regardless of which
    // listener tripped the shutdown.
    if let Err(err) = runtime.audit_sink.flush().await {
        warn!(error = %err, "audit flush on shutdown failed");
    }

    refresh_shutdown.cancel();
    while let Some(joined) = refresh_tasks.join_next().await {
        if let Err(err) = joined {
            warn!(error = %err, "refresh task failed during shutdown");
        }
    }

    result
}

async fn run_openapi(
    config_path: PathBuf,
    env_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    load_env_file_arg(env_file.as_deref())?;
    let config = config::load(&config_path)?;
    let registry = EntityRegistry::from_config(&config)?;
    let document = registry_relay::api::openapi::release_artifact_document(&config, &registry);
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

async fn run_doctor(
    config_path: PathBuf,
    env_file: Option<PathBuf>,
    format: OutputFormat,
    profile_override: Option<DeploymentProfile>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match format {
        OutputFormat::Json => {
            let report = build_doctor_report(&config_path, env_file.as_deref(), profile_override);
            println!("{}", serde_json::to_string_pretty(&report.output)?);
            if report.exit_success {
                Ok(())
            } else {
                Err(io::Error::other("registry-relay doctor failed").into())
            }
        }
    }
}

async fn run_explain_config(
    config_path: PathBuf,
    env_file: Option<PathBuf>,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match format {
        OutputFormat::Json => {
            load_env_file_arg(env_file.as_deref())?;
            let raw = fs::read_to_string(&config_path)?;
            let expanded = expand_config_env_vars(&raw)?;
            let resolved_config = redacted_resolved_config(&expanded)?;
            let config = config::load(&config_path)?;
            let report = json!({
                "schema_version": "registry.config.explanation.v1",
                "product": "registry-relay",
                "config_schema_version": RELAY_CONFIG_SCHEMA_VERSION,
                "source": {
                    "kind": "local_file",
                    "path": path_for_json(&config_path),
                },
                "required_env": required_env_report(&config),
                "defaults_applied": [],
                "optional_sections_absent": relay_optional_sections_absent(&config),
                "live_apply": relay_live_apply_classes(),
                "context_constraints": [],
                "resolved_config": resolved_config,
                "hashes": {
                    "internal_config_hash": internal_config_hash(raw.as_bytes()),
                },
                "generated_at": now_rfc3339(),
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

async fn run_schema(format: OutputFormat) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&lightweight_schema())?);
            Ok(())
        }
    }
}

fn build_doctor_report(
    config_path: &std::path::Path,
    env_file: Option<&std::path::Path>,
    profile_override: Option<DeploymentProfile>,
) -> DoctorReport {
    let raw_config = fs::read_to_string(config_path).ok();
    let mut checks = Vec::new();
    if let Some(env_file) = env_file {
        match load_env_file_arg(Some(env_file)) {
            Ok(()) => checks.push(DoctorCheck::passed(
                "env_file",
                "relay.env_file.loaded",
                "env file loaded",
                None,
            )),
            Err(_) => checks.push(DoctorCheck::failed(
                "env_file",
                "relay.env_file.failed",
                "env file could not be loaded",
                Some("check --env-file points to a readable KEY=VALUE file"),
            )),
        }
    }

    if checks.iter().any(|check| check.status == "failed") {
        return DoctorReport::new(
            checks,
            None,
            profile_override,
            config_path,
            raw_config.as_deref(),
        );
    }

    let loaded_config = match config::load_with_metadata(config_path) {
        Ok(loaded) => {
            checks.push(DoctorCheck::passed(
                "config",
                "relay.config.loaded",
                "config parsed and validated",
                None,
            ));
            match EntityRegistry::from_config(&loaded.runtime) {
                Ok(_) => checks.push(DoctorCheck::passed(
                    "entity_registry",
                    "relay.entity_registry.verified",
                    "entity registry semantic validation passed",
                    None,
                )),
                Err(_) => checks.push(DoctorCheck::failed(
                    "entity_registry",
                    "relay.entity_registry.failed",
                    "entity registry validation failed",
                    Some("check entity definitions, table mappings, and relationship targets"),
                )),
            }
            if loaded.metadata.is_some() {
                checks.push(DoctorCheck::passed(
                    "metadata",
                    "relay.metadata.loaded",
                    "split metadata manifest loaded and matched runtime bindings",
                    None,
                ));
            } else {
                checks.push(DoctorCheck::passed(
                    "metadata",
                    "relay.metadata.not_configured",
                    "split metadata manifest is not configured",
                    None,
                ));
            }
            if loaded.metadata_source_digest.is_some() {
                checks.push(DoctorCheck::passed(
                    "metadata_digest",
                    "relay.metadata.digest_verified",
                    "split metadata source digest is present",
                    None,
                ));
            }
            Some(loaded.runtime.clone())
        }
        Err(err) => {
            checks.push(DoctorCheck::failed(
                "config",
                err.code(),
                "config could not be loaded or validated",
                Some("fix the config file, required env vars, and split metadata bindings"),
            ));
            parse_doctor_config_without_validation(config_path)
        }
    };

    DoctorReport::new(
        checks,
        loaded_config.as_ref(),
        profile_override,
        config_path,
        raw_config.as_deref(),
    )
}

fn parse_doctor_config_without_validation(config_path: &std::path::Path) -> Option<Config> {
    let raw = fs::read_to_string(config_path).ok()?;
    let expanded = expand_config_env_vars(&raw).ok()?;
    serde_saphyr::from_str(&expanded).ok()
}

struct DoctorReport {
    output: Value,
    exit_success: bool,
}

impl DoctorReport {
    fn new(
        checks: Vec<DoctorCheck>,
        config: Option<&Config>,
        profile_override: Option<DeploymentProfile>,
        config_path: &std::path::Path,
        raw_config: Option<&str>,
    ) -> Self {
        let deployment_profile = resolve_deployment_profile(config, profile_override);
        let findings = deployment_findings(config, &deployment_profile);
        let exit_success = checks.iter().all(|check| check.status != "failed")
            && findings
                .iter()
                .all(|finding| !doctor_finding_fails(finding));
        let diagnostics = checks
            .iter()
            .map(doctor_check_diagnostic)
            .chain(findings.iter().map(doctor_finding_diagnostic))
            .collect::<Vec<_>>();
        let error_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic["severity"] == "error")
            .count();
        let warning_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic["severity"] == "warning")
            .count();
        let mut output = json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": "registry-relay",
            "config_schema_version": RELAY_CONFIG_SCHEMA_VERSION,
            "source": {
                "kind": "local_file",
                "path": path_for_json(config_path),
            },
            "status": if error_count > 0 {
                ReportStatus::Error.as_str()
            } else if warning_count > 0 {
                ReportStatus::Warning.as_str()
            } else {
                ReportStatus::Ok.as_str()
            },
            "summary": {
                "error_count": error_count,
                "warning_count": warning_count,
            },
            "diagnostics": diagnostics,
            "required_env": config.map(required_env_report).unwrap_or_default(),
            "context_constraints": [],
            "generated_at": now_rfc3339(),
        });
        if let Some(raw) = raw_config {
            output["hashes"] = json!({
                "internal_config_hash": internal_config_hash(raw.as_bytes()),
            });
        }
        Self {
            output,
            exit_success,
        }
    }
}

fn doctor_finding_fails(finding: &DoctorFinding) -> bool {
    finding.status == "active" && matches!(finding.severity, "startup_fail" | "readiness_fail")
}

#[derive(Debug, Serialize)]
struct DeploymentProfileReport {
    value: Option<&'static str>,
    source: &'static str,
}

#[derive(Debug, Serialize)]
struct DoctorFinding {
    id: String,
    severity: &'static str,
    status: &'static str,
    message: &'static str,
}

fn resolve_deployment_profile(
    config: Option<&Config>,
    profile_override: Option<DeploymentProfile>,
) -> DeploymentProfileReport {
    if let Some(profile) = profile_override {
        return DeploymentProfileReport {
            value: Some(profile.as_str()),
            source: "override",
        };
    }
    if let Some(profile) = config.and_then(|config| config.deployment.profile) {
        return DeploymentProfileReport {
            value: Some(profile.as_str()),
            source: "config",
        };
    }
    DeploymentProfileReport {
        value: None,
        source: "undeclared",
    }
}

fn deployment_findings(
    config: Option<&Config>,
    deployment_profile: &DeploymentProfileReport,
) -> Vec<DoctorFinding> {
    let Some(config) = config else {
        if deployment_profile.value.is_none() {
            return vec![DoctorFinding {
                id: "deployment.profile_undeclared".to_string(),
                severity: "startup_fail",
                status: "active",
                message: "set deployment.profile: local for development, or production/evidence_grade for deployment",
            }];
        }
        return Vec::new();
    };
    let profile = deployment_profile.value.and_then(|value| match value {
        "local" => Some(DeploymentProfile::Local),
        "hosted_lab" => Some(DeploymentProfile::HostedLab),
        "production" => Some(DeploymentProfile::Production),
        "evidence_grade" => Some(DeploymentProfile::EvidenceGrade),
        _ => None,
    });
    let facts = registry_relay::deployment::facts_from_config(config, ConfigSource::LocalFile);
    let waivers = registry_relay::deployment::waivers_from_config(config);
    registry_relay::deployment::evaluate(
        profile,
        &facts,
        &waivers,
        &registry_relay::deployment::today_utc(),
    )
    .findings
    .into_iter()
    .map(|finding| DoctorFinding {
        id: finding.id,
        severity: finding.severity.as_str(),
        status: finding.status.as_str(),
        message: "deployment profile gate evaluated",
    })
    .collect()
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: &'static str,
    status: &'static str,
    severity: &'static str,
    code: &'static str,
    message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'static str>,
}

impl DoctorCheck {
    fn passed(
        name: &'static str,
        code: &'static str,
        message: &'static str,
        action: Option<&'static str>,
    ) -> Self {
        Self {
            name,
            status: "passed",
            severity: "info",
            code,
            message,
            action,
        }
    }

    fn failed(
        name: &'static str,
        code: &'static str,
        message: &'static str,
        action: Option<&'static str>,
    ) -> Self {
        Self {
            name,
            status: "failed",
            severity: "error",
            code,
            message,
            action,
        }
    }
}

fn doctor_check_diagnostic(check: &DoctorCheck) -> Value {
    let mut message = check.message.to_string();
    if let Some(action) = check.action {
        message.push_str(" Next action: ");
        message.push_str(action);
    }
    json!({
        "code": check.code,
        "severity": check.severity,
        "message": message,
    })
}

fn doctor_finding_diagnostic(finding: &DoctorFinding) -> Value {
    json!({
        "code": finding.id,
        "severity": shared_severity(finding.severity),
        "message": format!(
            "{}: {} is {} at severity {}",
            finding.id, finding.message, finding.status, finding.severity
        ),
    })
}

fn shared_severity(severity: &str) -> &'static str {
    match severity {
        "startup_fail" | "readiness_fail" | "finding_error" | "error" => "error",
        "finding_warn" | "warning" => "warning",
        _ => "info",
    }
}

fn required_env_report(config: &Config) -> Vec<Value> {
    let mut envs = BTreeMap::new();
    if config.auth.mode == config::AuthMode::ApiKey {
        for api_key in &config.auth.api_keys {
            if api_key.fingerprint.provider == CredentialFingerprintProvider::Env {
                if let Some(name) = &api_key.fingerprint.name {
                    envs.insert(name.clone(), ConfigValueClassification::Secret);
                }
            }
        }
    }
    if let Some(hash_secret_env) = &config.audit.hash_secret_env {
        envs.insert(hash_secret_env.clone(), ConfigValueClassification::Secret);
    }
    if let Some(provenance) = &config.provenance {
        issuer_required_env(&provenance.issuer, &mut envs);
    }
    for dataset in &config.datasets {
        for table in dataset.table_configs() {
            if let SourceConfig::Postgres { connection_env, .. } = &table.source {
                envs.insert(connection_env.clone(), ConfigValueClassification::Secret);
            }
        }
    }
    envs.into_iter()
        .map(|(name, classification)| {
            json!({
                "name": name,
                "classification": classification.as_str(),
                "status": if env::var_os(&name).is_some() {
                    RequiredEnvStatus::Present.as_str()
                } else {
                    RequiredEnvStatus::Missing.as_str()
                },
            })
        })
        .collect()
}

fn issuer_required_env(
    issuer: &IssuerConfig,
    envs: &mut BTreeMap<String, ConfigValueClassification>,
) {
    match issuer {
        IssuerConfig::Gateway(config) => {
            signer_required_env(&config.signer, envs);
            for retired_key in &config.retired_keys {
                envs.insert(
                    retired_key.jwk_env.clone(),
                    ConfigValueClassification::Public,
                );
            }
        }
        IssuerConfig::Delegated(config) => {
            signer_required_env(&config.signer, envs);
            for retired_key in &config.retired_keys {
                envs.insert(
                    retired_key.jwk_env.clone(),
                    ConfigValueClassification::Public,
                );
            }
        }
        _ => {}
    }
}

fn signer_required_env(
    signer: &SignerConfig,
    envs: &mut BTreeMap<String, ConfigValueClassification>,
) {
    if let SignerConfig::Software(config) = signer {
        envs.insert(config.jwk_env.clone(), ConfigValueClassification::Secret);
    }
}

fn relay_optional_sections_absent(config: &Config) -> Vec<Value> {
    let mut sections = Vec::new();
    if config.config_trust.is_none() {
        sections.push(json!({
            "path": "config_trust",
            "reason": "signed config apply is disabled",
        }));
    }
    if config.metadata.is_none() {
        sections.push(json!({
            "path": "metadata",
            "reason": "split metadata manifest is not configured",
        }));
    }
    if config.provenance.is_none() {
        sections.push(json!({
            "path": "provenance",
            "reason": "signed response credentials are disabled",
        }));
    }
    sections
}

fn relay_live_apply_classes() -> Vec<Value> {
    [
        ("auth.api_keys", LiveApplyClass::HotSwappable),
        ("auth.oidc", LiveApplyClass::HotSwappable),
        ("audit", LiveApplyClass::HotSwappable),
        ("catalog", LiveApplyClass::HotSwappable),
        ("provenance.issuer.signer", LiveApplyClass::HotSwappable),
        ("datasets", LiveApplyClass::RestartRequired),
        ("server.bind", LiveApplyClass::RestartRequired),
        ("server.admin_bind", LiveApplyClass::RestartRequired),
        ("config_trust", LiveApplyClass::RestartRequired),
    ]
    .into_iter()
    .map(|(path, class)| {
        json!({
            "path": path,
            "class": class.as_str(),
        })
    })
    .collect()
}

fn redacted_resolved_config(
    expanded_yaml: &str,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let value: Value = serde_saphyr::from_str(expanded_yaml)?;
    Ok(redact_config_value(
        &value,
        relay_config_value_classification,
    ))
}

fn relay_config_value_classification(path: &[&str], value: &Value) -> ConfigValueClassification {
    if !matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    ) {
        return ConfigValueClassification::Public;
    }

    // Value-level defense, independent of the key name: a leaf string whose
    // value is a URL carrying userinfo (`user:pass@host` or `user@host`) is a
    // secret regardless of the key it lives under. This is the core defense
    // against e.g. `jwks_url: ${URL_WITH_BASIC_AUTH}` expanding to a URL with
    // embedded credentials under a key that is not otherwise a trigger word.
    if let Value::String(text) = value {
        if url_contains_userinfo(text) {
            return ConfigValueClassification::Secret;
        }
    }

    let Some(key) = path.last() else {
        return ConfigValueClassification::Public;
    };
    let key = key.to_ascii_lowercase();
    if key.contains("secret")
        || key.contains("password")
        || key.contains("token")
        || key.contains("private")
        || key.contains("passphrase")
        || key.contains("credential")
    {
        return ConfigValueClassification::Secret;
    }
    if key.contains("connection")
        || key.contains("dsn")
        || key.contains("url")
        || key.contains("uri")
        || key == "jwk"
    {
        return ConfigValueClassification::Secret;
    }
    if key.contains("key") {
        // `key` substring is broad; carve out well-known public key material so
        // harmless values stay public. Hard secret markers above still win.
        if is_public_key_name(&key) {
            return ConfigValueClassification::Public;
        }
        return ConfigValueClassification::Secret;
    }
    ConfigValueClassification::Public
}

/// Returns true for key names that contain `key` but denote *public* key
/// material (or a JWKS endpoint key id), so the broad `key` substring match
/// does not redact values that are safe to print.
fn is_public_key_name(key: &str) -> bool {
    key.contains("public")
        || key.contains("pubkey")
        || key == "kid"
        || key == "key_id"
        || key == "keyid"
}

/// Robust, dependency-free detection of a URL string carrying a userinfo
/// component (`user:password@host` or `user@host`). We deliberately avoid
/// matching bare `@` (e.g. email addresses) by requiring a `scheme://`
/// prefix and locating the `@` within the authority — that is, before the
/// first `/`, `?`, or `#` that ends the authority.
fn url_contains_userinfo(value: &str) -> bool {
    let value = value.trim();
    // Require a `scheme://` prefix so a bare `@` (e.g. an email address) is
    // not matched as userinfo.
    let Some((scheme, authority_and_rest)) = value.split_once("://") else {
        return false;
    };
    // A scheme must be non-empty and a valid scheme token to avoid matching
    // arbitrary text that merely happens to contain `://`.
    if scheme.is_empty()
        || !scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return false;
    }
    // The authority ends at the first `/`, `?`, or `#`.
    let authority_end = authority_and_rest
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_rest.len());
    authority_and_rest[..authority_end].contains('@')
}

fn path_for_json(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("system clock timestamp formats as RFC3339")
}

async fn run_config_verify_bundle(
    command: ConfigVerifyBundleCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let verified = match verify_config_bundle(&command.bundle_dir, &command.anchor_path) {
        Ok(verified) => verified,
        Err(error) => {
            let result = bundle_verify_rejection_result(&error);
            print_json_report(config_verify_bundle_report(
                result,
                "unknown",
                None,
                None,
                None,
                None,
                Some((result, error.to_string())),
            ))?;
            return Err(Box::new(error));
        }
    };
    let key = AntiRollbackKey {
        product: verified.manifest.product.clone(),
        instance_id: verified.manifest.instance_id.clone().unwrap_or_default(),
        environment: verified.manifest.environment.clone(),
        stream_id: verified.manifest.stream_id.clone(),
    };
    if let Err(error) = verify_bundle_state_read_only(
        &command.state_path,
        &key,
        verified.manifest.sequence,
        &verified.manifest.config_hash,
    ) {
        print_json_report(config_verify_bundle_report(
            "rejected_rollback",
            &verified.manifest.stream_id,
            Some(verified.manifest.bundle_id.clone()),
            Some(verified.manifest.sequence),
            verified.manifest.previous_config_hash.clone(),
            Some(verified.manifest.config_hash.clone()),
            Some(("rejected_rollback", error.to_string())),
        ))?;
        return Err(error);
    }
    let config_text = std::str::from_utf8(&verified.config_bytes)?;
    let (_config, provenance) = match parse_candidate_config_with_provenance(
        config_text,
        &verified.manifest.bundle_id,
        verified.manifest.sequence,
        ConfigSource::SignedBundleFile,
    ) {
        Ok(parsed) => parsed,
        Err(detail) => {
            print_json_report(config_verify_bundle_report(
                "rejected_validation",
                &verified.manifest.stream_id,
                Some(verified.manifest.bundle_id.clone()),
                Some(verified.manifest.sequence),
                verified.manifest.previous_config_hash.clone(),
                Some(verified.manifest.config_hash.clone()),
                Some(("rejected_validation", detail.to_string())),
            ))?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, detail).into());
        }
    };

    let _ = provenance;
    print_json_report(config_verify_bundle_report(
        "verified",
        &verified.manifest.stream_id,
        Some(verified.manifest.bundle_id),
        Some(verified.manifest.sequence),
        verified.manifest.previous_config_hash,
        Some(verified.manifest.config_hash),
        None,
    ))?;
    Ok(())
}

fn verify_bundle_state_read_only(
    state_path: &PathBuf,
    key: &AntiRollbackKey,
    sequence: u64,
    config_hash: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let record = FileAntiRollbackStore::new(state_path).load(key)?;
    if sequence > record.last_sequence
        || (sequence == record.last_sequence && config_hash == record.last_config_hash)
        || record.override_pin.as_ref().is_some_and(|pin| {
            override_pin_active_and_unexpired(pin) && pin.config_hash == config_hash
        })
    {
        Ok(())
    } else {
        Err("signed config bundle sequence is not monotonic".into())
    }
}

fn bundle_verify_rejection_result(error: &ConfigBundleError) -> &'static str {
    match error {
        ConfigBundleError::BindingMismatch(_) => "rejected_binding",
        ConfigBundleError::SignatureRejected
        | ConfigBundleError::InvalidSignatureEnvelope(_)
        | ConfigBundleError::InvalidTrustAnchor(_)
        | ConfigBundleError::InvalidPermissions(_) => "rejected_signature",
        ConfigBundleError::Io(_)
        | ConfigBundleError::Json(_)
        | ConfigBundleError::InvalidManifest(_)
        | ConfigBundleError::InvalidBreakGlass(_)
        | ConfigBundleError::FileClosure(_)
        | ConfigBundleError::HashMismatch { .. } => "rejected_validation",
    }
}

fn print_json_report(value: Value) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn config_verify_bundle_report(
    result: &'static str,
    stream_id: &str,
    bundle_id: Option<String>,
    bundle_sequence: Option<u64>,
    previous_config_hash: Option<String>,
    config_hash: Option<String>,
    error: Option<(&'static str, String)>,
) -> Value {
    let errors = error
        .map(|(code, message)| vec![json!({ "code": code, "message": message })])
        .unwrap_or_default();
    json!({
        "schema": "registry.platform.config_apply_report.v1",
        "attempt_id": Ulid::new().to_string(),
        "component": "registry-relay",
        "stream_id": stream_id,
        "source": ConfigSource::SignedBundleFile.as_posture_str(),
        "bundle_id": bundle_id,
        "bundle_sequence": bundle_sequence,
        "previous_config_hash": previous_config_hash,
        "config_hash": config_hash,
        "result": result,
        "restart_required": false,
        "change_classes": [],
        "affected_components": [],
        "warnings": [],
        "errors": errors,
    })
}

/// Offline audit-chain recovery (#196). Quarantines a retained chain that no
/// longer verifies under the configured keyed hasher and starts a fresh,
/// anchored segment. Refuses to run while a relay holds the single-writer lock.
async fn run_audit_quarantine(
    config_path: PathBuf,
    env_file: Option<PathBuf>,
    reason: String,
    operator: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    load_env_file_arg(env_file.as_deref())?;
    let config = config::load(&config_path)?;
    let (path, max_files) = match &config.audit.sink {
        AuditSinkConfig::File { path, rotate } => (path.clone(), rotate.max_files),
        _ => {
            return Err(io::Error::other(
                "audit quarantine requires a file audit sink (audit.sink: file)",
            )
            .into());
        }
    };
    let hash_secret_env = config.audit.hash_secret_env.as_deref().ok_or_else(|| {
        io::Error::other("audit.hash_secret_env is required to verify the audit chain")
    })?;
    let profile = AuditChainProfile::registry_relay_from_env(hash_secret_env)?;
    let now_unix_ms = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX);
    let outcome = registry_platform_audit::quarantine_and_recover_chain(
        &path,
        max_files,
        &profile.hasher(),
        &reason,
        operator.as_deref(),
        now_unix_ms,
    )?;
    let report = json!({
        "schema_version": "registry.audit.recovery.v1",
        "product": "registry-relay",
        "audit_path": path_for_json(&path),
        "already_consistent": outcome.already_consistent,
        "first_bad_line": outcome.first_bad_line,
        "last_good_hash": outcome
            .last_good_hash
            .map(|hash| registry_platform_audit::OptionalHashHex(Some(hash)).to_string()),
        "break_event_hash": outcome
            .break_event_hash
            .map(|hash| registry_platform_audit::OptionalHashHex(Some(hash)).to_string()),
        "records_before_break": outcome.records_before_break,
        "quarantine_suffix": outcome.quarantine_suffix,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
async fn compile_relay_runtime(
    config_path: PathBuf,
    bind_override: Option<SocketAddr>,
) -> Result<RelayRuntimeSnapshot, Box<dyn std::error::Error + Send + Sync>> {
    compile_relay_runtime_with_options(config_path, bind_override, config::LoadOptions::default())
        .await
}

async fn compile_relay_runtime_with_options(
    config_path: PathBuf,
    bind_override: Option<SocketAddr>,
    load_options: config::LoadOptions,
) -> Result<RelayRuntimeSnapshot, Box<dyn std::error::Error + Send + Sync>> {
    info!(path = %config_path.display(), "loading registry-relay config");

    let loaded = config::load_with_metadata_options(&config_path, load_options)?;
    let config_provenance = loaded.provenance.clone();
    let pending_bundle_acceptance = loaded.pending_bundle_acceptance.clone();
    let compiled_metadata = loaded.metadata.map(Arc::new);
    let metadata_source_digest = loaded.metadata_source_digest;
    let config = Arc::new(loaded.runtime);

    let auth = build_auth(&config).await?;
    let audit_sink = build_audit_sink(&config)?;
    // Eagerly verify the retained audit chain so a chain bricked by an earlier
    // fork surfaces as an actionable /ready signal instead of a per-request 503
    // behind a green healthcheck (#196). Startup is not aborted: readiness
    // reports not-ready until the operator recovers with `registry-relay audit
    // quarantine`.
    if let Err(err) = audit_sink.verify_chain_eager().await {
        error!(
            code = registry_relay::audit::AUDIT_CHAIN_INCONSISTENT_CODE,
            error = %err,
            "audit chain failed startup verification; /ready will report not-ready until it is recovered"
        );
    }
    if let Some(acceptance) = &pending_bundle_acceptance {
        write_boot_config_audits(&audit_sink, acceptance).await?;
        persist_bundle_acceptance(acceptance)?;
    }
    // Boot-time validation already logged waived gates; now that the audit
    // pipeline exists, record them durably. The startup path loads config
    // from a local file, matching the source `validate::run` evaluated.
    registry_relay::server::audit_waived_deployment_gates(
        &config,
        &audit_sink,
        ConfigSource::LocalFile,
    )
    .await?;
    let bind: SocketAddr = bind_override.unwrap_or(config.server.bind);
    let admin_bind: Option<SocketAddr> = config.server.admin_bind;
    let audit_kind = audit_sink_kind(&config);
    let df_ctx = Arc::new(SessionContext::new());
    let formats = Arc::new(FormatRegistry::with_v1_defaults());
    let cache_root = Arc::from(config.server.cache_dir.as_path());
    let ingest = Arc::new(IngestRegistry::from_config(
        &config,
        formats,
        cache_root,
        Arc::clone(&df_ctx),
    )?);
    let entity_registry = Arc::new(EntityRegistry::from_config(&config)?);
    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
        Arc::clone(&config),
    ));
    let initial_snapshot = ingest.snapshot();
    let (readiness_tx, readiness_rx) = watch::channel::<ReadinessSnapshot>(initial_snapshot);
    let cursor_signer = Arc::new(registry_relay::runtime_config::CursorSigner::new_random());

    // Build provenance state from the parsed config.
    // `build_resolved_provenance_config` returns:
    //   * `Ok(None)` when the operator omitted the `provenance:` block
    //     or set `enabled: false`, leaving the binary unchanged and
    //     requiring no signing secrets.
    //   * `Ok(Some(_))` only when provenance is enabled and signer
    //     material has loaded successfully.
    let provenance_state: Option<Arc<ProvenanceState>> =
        build_resolved_provenance_config(config.provenance.as_ref())?
            .map(|resolved: ResolvedProvenanceConfig| Arc::new(ProvenanceState::new(resolved)));
    let publicschema_registry = build_publicschema_registry(&config)?.map(Arc::new);
    #[cfg(feature = "spdci-api-standards")]
    let spdci_response_mapper = build_spdci_response_mapper(&config)?.map(Arc::new);
    let metrics = RequestMetrics::shared();

    Ok(RelayRuntimeSnapshot::new(
        config,
        config_provenance,
        compiled_metadata,
        metadata_source_digest,
        None,
        auth,
        audit_sink,
        bind,
        admin_bind,
        audit_kind,
        df_ctx,
        ingest,
        entity_registry,
        query,
        aggregate_query,
        readiness_tx,
        readiness_rx,
        cursor_signer,
        provenance_state,
        publicschema_registry,
        #[cfg(feature = "spdci-api-standards")]
        spdci_response_mapper,
        metrics,
    ))
}

async fn write_boot_config_audits(
    audit_sink: &AuditPipeline,
    acceptance: &config::PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if matches!(
        acceptance.state_action,
        config::BundleStateAction::PersistOverridePin
    ) {
        write_break_glass_used_audit(audit_sink, acceptance).await?;
        if acceptance.source != ConfigSource::SignedBundleFile {
            return Ok(());
        }
    }
    if acceptance.source != ConfigSource::SignedBundleFile {
        return Ok(());
    }
    write_bundle_acceptance_audit(audit_sink, acceptance).await
}

async fn write_bundle_acceptance_audit(
    audit_sink: &AuditPipeline,
    acceptance: &config::PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let audit = ConfigAuditExt {
        action: "boot",
        source: acceptance.source.as_posture_str(),
        bundle_id: acceptance.bundle_id.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        product_validation_result: "accepted",
        apply_result: "applied",
        posture_result: "accepted",
        applied: true,
        restart_required: false,
        change_classes: Vec::new(),
        break_glass: acceptance.break_glass,
        break_glass_approval_reference: None,
        break_glass_approved_by: None,
        break_glass_reason_hash: None,
        break_glass_emergency_change_class: None,
        break_glass_expires_at_unix_seconds: None,
        break_glass_rate_limit_identity: None,
        local_approval_reference: None,
        local_approval_approved_by: None,
        local_approval_reason_hash: None,
        local_approval_change_class: None,
        local_approval_expires_at_unix_seconds: None,
        local_approval_rate_limit_identity: None,
    };
    audit_sink
        .write_operational_event(
            OperationalAuditEvent::success("config.bundle_accepted").with_config(audit),
        )
        .await?;
    Ok(())
}

async fn write_break_glass_used_audit(
    audit_sink: &AuditPipeline,
    acceptance: &config::PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pin = acceptance
        .override_pin
        .as_ref()
        .ok_or("break-glass acceptance is missing override pin")?;
    let audit = ConfigAuditExt {
        action: "boot",
        source: acceptance.source.as_posture_str(),
        bundle_id: acceptance.bundle_id.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        product_validation_result: "accepted",
        apply_result: "applied",
        posture_result: "accepted",
        applied: true,
        restart_required: false,
        change_classes: Vec::new(),
        break_glass: true,
        break_glass_approval_reference: None,
        break_glass_approved_by: Some(pin.operator.clone()),
        break_glass_reason_hash: Some(internal_config_hash(pin.reason.as_bytes())),
        break_glass_emergency_change_class: Some(match pin.mode {
            ConfigOverrideMode::AcceptRollback => "accept_rollback".to_string(),
            ConfigOverrideMode::AcceptUnsigned => "accept_unsigned".to_string(),
        }),
        break_glass_expires_at_unix_seconds: pin.expires_at.as_deref().and_then(rfc3339_unix),
        break_glass_rate_limit_identity: None,
        local_approval_reference: None,
        local_approval_approved_by: None,
        local_approval_reason_hash: None,
        local_approval_change_class: None,
        local_approval_expires_at_unix_seconds: None,
        local_approval_rate_limit_identity: None,
    };
    audit_sink
        .write_operational_event(
            OperationalAuditEvent::success("config.break_glass_used").with_config(audit),
        )
        .await?;
    Ok(())
}

fn rfc3339_unix(value: &str) -> Option<u64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
}

fn persist_bundle_acceptance(
    acceptance: &config::PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = FileAntiRollbackStore::new(&acceptance.state_path);
    match acceptance.state_action {
        config::BundleStateAction::Initialize => {
            store.initialize(acceptance.initial_record())?;
        }
        config::BundleStateAction::Accept => {
            store.accept_bundle(
                &acceptance.key,
                acceptance
                    .bundle_id
                    .clone()
                    .ok_or("signed bundle acceptance is missing bundle_id")?,
                acceptance
                    .sequence
                    .ok_or("signed bundle acceptance is missing sequence")?,
                acceptance.config_hash.clone(),
            )?;
        }
        config::BundleStateAction::PersistOverridePin => {
            let pin = acceptance
                .override_pin
                .clone()
                .ok_or("break-glass acceptance is missing override pin")?;
            store.persist_override_pin(&acceptance.key, pin)?;
            if let Some(path) = &acceptance.override_path {
                consume_break_glass_override(path)?;
            }
        }
        config::BundleStateAction::AlreadyPinned => {
            if let Some(path) = &acceptance.override_path {
                consume_break_glass_override(path)?;
            }
        }
    }
    Ok(())
}

fn consume_break_glass_override(
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("break-glass override path has no file name")?;
    let consumed_name = format!("{file_name}.consumed-{}", Ulid::new());
    let consumed_path = path.with_file_name(consumed_name);
    fs::rename(path, consumed_path)?;
    Ok(())
}

fn build_relay_app_from_runtime(
    handle: Arc<RelayRuntimeHandle>,
) -> Result<axum::Router, Box<dyn std::error::Error + Send + Sync>> {
    let runtime = handle.load_full();
    let auth: AuthProviderRef = Arc::new(RuntimeAuthProvider::new(Arc::clone(&handle)));
    let mut app =
        registry_relay::server::build_app_with_entity_query_metadata_provenance_and_metrics(
            Arc::clone(&runtime.config),
            auth,
            Arc::clone(&runtime.audit_sink),
            runtime.readiness_rx.clone(),
            Arc::clone(&runtime.entity_registry),
            Arc::clone(&runtime.query),
            Arc::clone(&runtime.aggregate_query),
            runtime.compiled_metadata.clone(),
            runtime.provenance_state.clone(),
            Arc::clone(&runtime.metrics),
        )?;
    if let Some(publicschema_registry) = &runtime.publicschema_registry {
        app = app.layer(Extension(Arc::clone(publicschema_registry)));
    }
    #[cfg(feature = "spdci-api-standards")]
    if let Some(spdci_response_mapper) = &runtime.spdci_response_mapper {
        app = app.layer(Extension(Arc::clone(spdci_response_mapper)));
    }
    Ok(app.layer(Extension(handle)))
}

fn parse_cli_command_from(args: Vec<String>) -> Result<CliCommand, CliError> {
    let mut args = args.into_iter();
    let _program = args.next();
    let rest: Vec<String> = args.collect();
    if rest
        .first()
        .is_some_and(|arg| arg == "--version" || arg == "-V")
    {
        // Match clap's built-in version flag: print the version and ignore any
        // trailing arguments rather than rejecting them, so the version surface
        // is consistent across registry-notary, registryctl, and registry-relay.
        Ok(CliCommand::Version)
    } else if rest.first().is_some_and(|arg| arg == HEALTHCHECK_COMMAND) {
        parse_healthcheck_command(&rest[1..])
    } else if rest
        .first()
        .is_some_and(|arg| arg == GENERATE_API_KEY_COMMAND)
    {
        parse_generate_api_key_command(&rest[1..])
    } else if rest.first().is_some_and(|arg| arg == OPENAPI_COMMAND) {
        parse_openapi_command(&rest[1..])
    } else if rest.first().is_some_and(|arg| arg == DOCTOR_COMMAND) {
        parse_doctor_command(&rest[1..])
    } else if rest
        .first()
        .is_some_and(|arg| arg == EXPLAIN_CONFIG_COMMAND)
    {
        parse_explain_config_command(&rest[1..])
    } else if rest.first().is_some_and(|arg| arg == SCHEMA_COMMAND) {
        parse_schema_command(&rest[1..])
    } else if rest.first().is_some_and(|arg| arg == CONFIG_COMMAND) {
        parse_config_command(&rest[1..])
    } else if rest.first().is_some_and(|arg| arg == AUDIT_COMMAND) {
        parse_audit_command(&rest[1..])
    } else {
        parse_serve_command(&rest)
    }
}

fn parse_audit_command(args: &[String]) -> Result<CliCommand, CliError> {
    match args.first().map(String::as_str) {
        Some(sub) if sub == QUARANTINE_SUBCOMMAND => parse_audit_quarantine_command(&args[1..]),
        Some(other) => Err(CliError(format!(
            "unknown {AUDIT_COMMAND} subcommand: {other} (expected {QUARANTINE_SUBCOMMAND})"
        ))),
        None => Err(CliError(format!(
            "{AUDIT_COMMAND} requires a subcommand (expected {QUARANTINE_SUBCOMMAND})"
        ))),
    }
}

fn parse_audit_quarantine_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut config_path: Option<PathBuf> = None;
    let mut env_file: Option<PathBuf> = None;
    let mut reason: Option<String> = None;
    let mut operator: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, CONFIG_FLAG) {
            config_path = Some(required_path_value(CONFIG_FLAG, value)?);
        } else if arg == CONFIG_FLAG {
            index += 1;
            config_path = Some(required_path_arg(args, index, CONFIG_FLAG)?);
        } else if let Some(value) = flag_value(arg, ENV_FILE_FLAG) {
            env_file = Some(required_path_value(ENV_FILE_FLAG, value)?);
        } else if arg == ENV_FILE_FLAG {
            index += 1;
            env_file = Some(required_path_arg(args, index, ENV_FILE_FLAG)?);
        } else if let Some(value) = flag_value(arg, REASON_FLAG) {
            reason = Some(required_string_value(REASON_FLAG, value)?);
        } else if arg == REASON_FLAG {
            index += 1;
            reason = Some(required_string_arg(args, index, REASON_FLAG)?);
        } else if let Some(value) = flag_value(arg, OPERATOR_FLAG) {
            operator = Some(required_string_value(OPERATOR_FLAG, value)?);
        } else if arg == OPERATOR_FLAG {
            index += 1;
            operator = Some(required_string_arg(args, index, OPERATOR_FLAG)?);
        } else {
            return Err(CliError(format!(
                "unknown {AUDIT_COMMAND} {QUARANTINE_SUBCOMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }
    if env_file.is_none() {
        env_file = default_env_file_from_env();
    }
    let reason = reason.ok_or_else(|| {
        CliError(format!(
            "{AUDIT_COMMAND} {QUARANTINE_SUBCOMMAND} requires {REASON_FLAG}"
        ))
    })?;
    Ok(CliCommand::AuditQuarantine {
        config_path: config_path.unwrap_or_else(default_config_path_from_env),
        env_file,
        reason,
        operator,
    })
}

fn parse_openapi_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut config_path: Option<PathBuf> = None;
    let mut env_file: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, CONFIG_FLAG) {
            config_path = Some(required_path_value(CONFIG_FLAG, value)?);
        } else if arg == CONFIG_FLAG {
            index += 1;
            config_path = Some(required_path_arg(args, index, CONFIG_FLAG)?);
        } else if let Some(value) = flag_value(arg, ENV_FILE_FLAG) {
            env_file = Some(required_path_value(ENV_FILE_FLAG, value)?);
        } else if arg == ENV_FILE_FLAG {
            index += 1;
            env_file = Some(required_path_arg(args, index, ENV_FILE_FLAG)?);
        } else {
            return Err(CliError(format!(
                "unknown {OPENAPI_COMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }
    if env_file.is_none() {
        env_file = default_env_file_from_env();
    }
    Ok(CliCommand::Openapi {
        config_path: config_path.unwrap_or_else(default_config_path_from_env),
        env_file,
    })
}

fn parse_doctor_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut config_path: Option<PathBuf> = None;
    let mut env_file: Option<PathBuf> = None;
    let mut format = OutputFormat::Json;
    let mut profile_override: Option<DeploymentProfile> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, CONFIG_FLAG) {
            config_path = Some(required_path_value(CONFIG_FLAG, value)?);
        } else if arg == CONFIG_FLAG {
            index += 1;
            config_path = Some(required_path_arg(args, index, CONFIG_FLAG)?);
        } else if let Some(value) = flag_value(arg, ENV_FILE_FLAG) {
            env_file = Some(required_path_value(ENV_FILE_FLAG, value)?);
        } else if arg == ENV_FILE_FLAG {
            index += 1;
            env_file = Some(required_path_arg(args, index, ENV_FILE_FLAG)?);
        } else if let Some(value) = flag_value(arg, FORMAT_FLAG) {
            format = parse_output_format(required_string_value(FORMAT_FLAG, value)?)?;
        } else if arg == FORMAT_FLAG {
            index += 1;
            format = parse_output_format(required_string_arg(args, index, FORMAT_FLAG)?)?;
        } else if let Some(value) = flag_value(arg, PROFILE_FLAG) {
            profile_override = Some(parse_deployment_profile(required_string_value(
                PROFILE_FLAG,
                value,
            )?)?);
        } else if arg == PROFILE_FLAG {
            index += 1;
            profile_override = Some(parse_deployment_profile(required_string_arg(
                args,
                index,
                PROFILE_FLAG,
            )?)?);
        } else {
            return Err(CliError(format!(
                "unknown {DOCTOR_COMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }
    if env_file.is_none() {
        env_file = default_env_file_from_env();
    }
    Ok(CliCommand::Doctor {
        config_path: config_path.unwrap_or_else(default_config_path_from_env),
        env_file,
        format,
        profile_override,
    })
}

fn parse_explain_config_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut config_path: Option<PathBuf> = None;
    let mut env_file: Option<PathBuf> = None;
    let mut format = OutputFormat::Json;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, CONFIG_FLAG) {
            config_path = Some(required_path_value(CONFIG_FLAG, value)?);
        } else if arg == CONFIG_FLAG {
            index += 1;
            config_path = Some(required_path_arg(args, index, CONFIG_FLAG)?);
        } else if let Some(value) = flag_value(arg, ENV_FILE_FLAG) {
            env_file = Some(required_path_value(ENV_FILE_FLAG, value)?);
        } else if arg == ENV_FILE_FLAG {
            index += 1;
            env_file = Some(required_path_arg(args, index, ENV_FILE_FLAG)?);
        } else if let Some(value) = flag_value(arg, FORMAT_FLAG) {
            format = parse_output_format(required_string_value(FORMAT_FLAG, value)?)?;
        } else if arg == FORMAT_FLAG {
            index += 1;
            format = parse_output_format(required_string_arg(args, index, FORMAT_FLAG)?)?;
        } else {
            return Err(CliError(format!(
                "unknown {EXPLAIN_CONFIG_COMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }
    if env_file.is_none() {
        env_file = default_env_file_from_env();
    }
    Ok(CliCommand::ExplainConfig {
        config_path: config_path.unwrap_or_else(default_config_path_from_env),
        env_file,
        format,
    })
}

fn parse_schema_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut format = OutputFormat::Json;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, FORMAT_FLAG) {
            format = parse_output_format(required_string_value(FORMAT_FLAG, value)?)?;
        } else if arg == FORMAT_FLAG {
            index += 1;
            format = parse_output_format(required_string_arg(args, index, FORMAT_FLAG)?)?;
        } else {
            return Err(CliError(format!(
                "unknown {SCHEMA_COMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }
    Ok(CliCommand::Schema { format })
}

fn parse_output_format(value: String) -> Result<OutputFormat, CliError> {
    match value.as_str() {
        "json" => Ok(OutputFormat::Json),
        _ => Err(CliError(format!("{FORMAT_FLAG} must be json"))),
    }
}

fn lightweight_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Registry Relay config",
        "type": "object",
        "required": ["server", "catalog", "auth", "audit", "datasets"],
        "properties": {
            "instance": { "type": "object" },
            "server": { "type": "object" },
            "config_trust": { "type": "object" },
            "metadata": { "type": "object" },
            "catalog": { "type": "object" },
            "vocabularies": { "type": "object" },
            "auth": { "type": "object" },
            "audit": { "type": "object" },
            "datasets": { "type": "array" },
            "provenance": { "type": "object" },
            "standards": { "type": "object" },
            "deployment": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn parse_deployment_profile(value: String) -> Result<DeploymentProfile, CliError> {
    match value.as_str() {
        "local" => Ok(DeploymentProfile::Local),
        "hosted_lab" => Ok(DeploymentProfile::HostedLab),
        "production" => Ok(DeploymentProfile::Production),
        "evidence_grade" => Ok(DeploymentProfile::EvidenceGrade),
        _ => Err(CliError(format!(
            "{PROFILE_FLAG} must be local, hosted_lab, production, or evidence_grade"
        ))),
    }
}

fn parse_serve_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut config_path: Option<PathBuf> = None;
    let mut env_file: Option<PathBuf> = None;
    let mut bind_override: Option<SocketAddr> = None;
    let mut initialize_state = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, CONFIG_FLAG) {
            config_path = Some(required_path_value(CONFIG_FLAG, value)?);
        } else if arg == CONFIG_FLAG {
            index += 1;
            config_path = Some(required_path_arg(args, index, CONFIG_FLAG)?);
        } else if let Some(value) = flag_value(arg, ENV_FILE_FLAG) {
            env_file = Some(required_path_value(ENV_FILE_FLAG, value)?);
        } else if arg == ENV_FILE_FLAG {
            index += 1;
            env_file = Some(required_path_arg(args, index, ENV_FILE_FLAG)?);
        } else if let Some(value) = flag_value(arg, BIND_FLAG) {
            bind_override = Some(parse_bind_value(value)?);
        } else if arg == BIND_FLAG {
            index += 1;
            bind_override = Some(parse_bind_value(required_string_arg(
                args, index, BIND_FLAG,
            )?)?);
        } else if arg == INITIALIZE_STATE_FLAG {
            initialize_state = true;
        } else {
            return Err(CliError(format!("unknown serve argument: {arg}")));
        }
        index += 1;
    }
    if env_file.is_none() {
        env_file = default_env_file_from_env();
    }
    if bind_override.is_none() {
        bind_override = default_bind_from_env()?;
    }
    Ok(CliCommand::Serve {
        config_path: config_path.unwrap_or_else(default_config_path_from_env),
        env_file,
        bind_override,
        initialize_state,
    })
}

fn parse_generate_api_key_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut id: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, ID_FLAG) {
            id = Some(required_api_key_id_value(ID_FLAG, value)?);
        } else if arg == ID_FLAG {
            index += 1;
            id = Some(required_api_key_id_arg(args, index, ID_FLAG)?);
        } else {
            return Err(CliError(format!(
                "unknown {GENERATE_API_KEY_COMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }

    Ok(CliCommand::GenerateApiKey(GenerateApiKeyCommand {
        id: require_flag(id, ID_FLAG)?,
    }))
}

fn parse_config_command(args: &[String]) -> Result<CliCommand, CliError> {
    let Some(command) = args.first() else {
        return Err(CliError(format!("{CONFIG_COMMAND} requires a subcommand")));
    };
    match command.as_str() {
        VERIFY_BUNDLE_COMMAND => parse_config_verify_bundle_command(&args[1..]),
        APPLY_BUNDLE_COMMAND => Err(CliError(
            "config apply-bundle is no longer supported by registry-relay".to_string(),
        )),
        _ => Err(CliError(format!(
            "unknown {CONFIG_COMMAND} subcommand: {command}"
        ))),
    }
}

fn parse_config_verify_bundle_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut bundle_dir: Option<PathBuf> = None;
    let mut anchor_path: Option<PathBuf> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, BUNDLE_DIR_FLAG) {
            bundle_dir = Some(required_path_value(BUNDLE_DIR_FLAG, value)?);
        } else if arg == BUNDLE_DIR_FLAG {
            index += 1;
            bundle_dir = Some(required_path_arg(args, index, BUNDLE_DIR_FLAG)?);
        } else if let Some(value) = flag_value(arg, ANCHOR_PATH_FLAG) {
            anchor_path = Some(required_path_value(ANCHOR_PATH_FLAG, value)?);
        } else if arg == ANCHOR_PATH_FLAG {
            index += 1;
            anchor_path = Some(required_path_arg(args, index, ANCHOR_PATH_FLAG)?);
        } else if let Some(value) = flag_value(arg, STATE_PATH_FLAG) {
            state_path = Some(required_path_value(STATE_PATH_FLAG, value)?);
        } else if arg == STATE_PATH_FLAG {
            index += 1;
            state_path = Some(required_path_arg(args, index, STATE_PATH_FLAG)?);
        } else {
            return Err(CliError(format!(
                "unknown {CONFIG_COMMAND} {VERIFY_BUNDLE_COMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }

    Ok(CliCommand::ConfigVerifyBundle(ConfigVerifyBundleCommand {
        bundle_dir: require_flag(bundle_dir, BUNDLE_DIR_FLAG)?,
        anchor_path: require_flag(anchor_path, ANCHOR_PATH_FLAG)?,
        state_path: require_flag(state_path, STATE_PATH_FLAG)?,
    }))
}

fn flag_value<'a>(arg: &'a str, flag: &str) -> Option<&'a str> {
    arg.strip_prefix(&format!("{flag}="))
}

fn required_path_arg(args: &[String], index: usize, flag: &str) -> Result<PathBuf, CliError> {
    let Some(value) = args.get(index) else {
        return Err(CliError(format!("{flag} requires a non-empty path")));
    };
    required_path_value(flag, value)
}

fn required_path_value(flag: &str, value: &str) -> Result<PathBuf, CliError> {
    if value.is_empty() {
        return Err(CliError(format!("{flag} requires a non-empty path")));
    }
    Ok(PathBuf::from(value))
}

fn required_string_arg(args: &[String], index: usize, flag: &str) -> Result<String, CliError> {
    let Some(value) = args.get(index) else {
        return Err(CliError(format!("{flag} requires a non-empty value")));
    };
    required_string_value(flag, value)
}

fn required_string_value(flag: &str, value: &str) -> Result<String, CliError> {
    if value.is_empty() {
        return Err(CliError(format!("{flag} requires a non-empty value")));
    }
    Ok(value.to_string())
}

fn required_api_key_id_arg(args: &[String], index: usize, flag: &str) -> Result<String, CliError> {
    let Some(value) = args.get(index) else {
        return Err(CliError(format!(
            "{flag} requires a lower-snake API key id"
        )));
    };
    required_api_key_id_value(flag, value)
}

fn required_api_key_id_value(flag: &str, value: &str) -> Result<String, CliError> {
    if !is_valid_api_key_id(value) {
        return Err(CliError(format!(
            "{flag} requires a lower-snake API key id"
        )));
    }
    Ok(value.to_string())
}

fn is_valid_api_key_id(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '_'))
}

fn require_flag<T>(value: Option<T>, flag: &str) -> Result<T, CliError> {
    value.ok_or_else(|| CliError(format!("{flag} is required")))
}

fn parse_healthcheck_command(args: &[String]) -> Result<CliCommand, CliError> {
    let mut url = DEFAULT_HEALTHCHECK_URL.to_string();
    let mut timeout_ms = DEFAULT_HEALTHCHECK_TIMEOUT_MS;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == HEALTHCHECK_URL_FLAG {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(CliError(format!(
                    "{HEALTHCHECK_URL_FLAG} requires a non-empty URL"
                )));
            };
            if value.is_empty() {
                return Err(CliError(format!(
                    "{HEALTHCHECK_URL_FLAG} requires a non-empty URL"
                )));
            }
            url = value.clone();
        } else if let Some(value) = arg.strip_prefix(&format!("{HEALTHCHECK_URL_FLAG}=")) {
            if value.is_empty() {
                return Err(CliError(format!(
                    "{HEALTHCHECK_URL_FLAG} requires a non-empty URL"
                )));
            }
            url = value.to_string();
        } else if arg == HEALTHCHECK_TIMEOUT_FLAG {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(CliError(format!(
                    "{HEALTHCHECK_TIMEOUT_FLAG} requires a positive integer"
                )));
            };
            timeout_ms = parse_timeout_ms(value)?;
        } else if let Some(value) = arg.strip_prefix(&format!("{HEALTHCHECK_TIMEOUT_FLAG}=")) {
            timeout_ms = parse_timeout_ms(value)?;
        } else {
            return Err(CliError(format!(
                "unknown {HEALTHCHECK_COMMAND} argument: {arg}"
            )));
        }
        index += 1;
    }

    Ok(CliCommand::Healthcheck {
        url,
        timeout: Duration::from_millis(timeout_ms),
    })
}

fn parse_timeout_ms(value: &str) -> Result<u64, CliError> {
    let timeout_ms = value.parse::<u64>().map_err(|_| {
        CliError(format!(
            "{HEALTHCHECK_TIMEOUT_FLAG} requires a positive integer"
        ))
    })?;
    if timeout_ms == 0 {
        return Err(CliError(format!(
            "{HEALTHCHECK_TIMEOUT_FLAG} requires a positive integer"
        )));
    }
    Ok(timeout_ms)
}

fn default_config_path_from_env() -> PathBuf {
    if let Ok(p) = env::var("REGISTRY_RELAY_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

fn default_env_file_from_env() -> Option<PathBuf> {
    env::var("REGISTRY_RELAY_ENV_FILE")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn default_bind_from_env() -> Result<Option<SocketAddr>, CliError> {
    let Ok(value) = env::var("REGISTRY_RELAY_BIND") else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    parse_bind_value(value).map(Some)
}

fn parse_bind_value(value: impl AsRef<str>) -> Result<SocketAddr, CliError> {
    let value = value.as_ref();
    value
        .parse::<SocketAddr>()
        .map_err(|_| CliError(format!("{BIND_FLAG} requires a socket address")))
}

fn load_env_file_arg(path: Option<&std::path::Path>) -> io::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let raw = fs::read_to_string(path)?;
    for (line_no, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("env file line {} must be KEY=VALUE", line_no + 1),
            ));
        };
        let key = key.trim();
        if !valid_env_key(key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("env file line {} has an invalid variable name", line_no + 1),
            ));
        }
        if env::var_os(key).is_none() {
            env::set_var(key, parse_env_file_value(value.trim()));
        }
    }
    Ok(())
}

fn parse_env_file_value(value: &str) -> String {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value
            .split_once(" #")
            .map(|(before, _)| before)
            .unwrap_or(value)
            .trim()
            .to_string()
    }
}

fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('_') | Some('A'..='Z') | Some('a'..='z'))
        && chars.all(|ch| matches!(ch, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

async fn run_healthcheck(
    url: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "healthcheck timeout must be greater than zero",
        )
        .into());
    }
    let client = reqwest::Client::builder().timeout(timeout).build()?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| io::Error::other(format!("healthcheck request failed: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(io::Error::other(format!("healthcheck returned status {status}")).into());
    }
    Ok(())
}

fn generate_api_key_output(id: &str) -> Result<String, CliError> {
    let mut bytes = [0_u8; registry_platform_authcommon::MIN_API_KEY_ENTROPY_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|err| CliError(format!("failed to generate API key material: {err}")))?;
    Ok(render_generated_api_key(id, &bytes))
}

fn render_generated_api_key(id: &str, bytes: &[u8]) -> String {
    let key = URL_SAFE_NO_PAD.encode(bytes);
    let fingerprint = fingerprint_api_key(&key);
    format!("api_key_id={id}\napi_key={key}\nfingerprint={fingerprint}")
}

/// Instantiate the configured audit sink.
fn build_audit_sink(config: &Config) -> Result<Arc<AuditPipeline>, Error> {
    let sink: Arc<dyn registry_platform_audit::AuditSink> = match &config.audit.sink {
        AuditSinkConfig::Stdout {} => Arc::new(StdoutSink::new()),
        AuditSinkConfig::File { path, rotate } => {
            match FileSink::new(path, rotate.max_size_mb, rotate.max_files) {
                Ok(sink) => Arc::new(sink),
                Err(err) => {
                    error!(
                        error = %err,
                        requested = "file",
                        path = %path.display(),
                        "configured audit file sink is unavailable"
                    );
                    return Err(Error::from(ConfigError::ValidationError));
                }
            }
        }
        AuditSinkConfig::Syslog {} => Arc::new(SyslogSink::new()),
        _ => {
            error!("unknown audit sink variant");
            return Err(Error::from(ConfigError::ValidationError));
        }
    };
    if !config.audit.chain {
        info!(
            "audit.chain is accepted for config compatibility; platform audit envelopes are always chained"
        );
    }
    let hash_secret_env = config
        .audit
        .hash_secret_env
        .as_deref()
        .ok_or(ConfigError::ValidationError)?;
    let profile = AuditChainProfile::registry_relay_from_env(hash_secret_env).map_err(|err| {
        error!(error = %err, "audit chain secret failed validation");
        ConfigError::ValidationError
    })?;
    Ok(Arc::new(AuditPipeline::new_with_chain_profile(
        sink, profile,
    )))
}

fn audit_sink_kind(config: &Config) -> &'static str {
    match &config.audit.sink {
        AuditSinkConfig::Stdout {} => "stdout",
        AuditSinkConfig::File { .. } => "file",
        AuditSinkConfig::Syslog {} => "syslog",
        _ => "unknown (fallback: stdout)",
    }
}

/// Initialise operational tracing on stderr. `RUST_LOG` controls the
/// filter and defaults to `info`. `REGISTRY_RELAY_LOG_FORMAT=json`
/// switches the default human-readable terminal output back to JSONL
/// for machine collection or redirected files.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match OperationalLogFormat::from_env() {
        OperationalLogFormat::Text => {
            let fmt_layer = fmt::layer()
                .compact()
                .with_target(false)
                .with_writer(std::io::stderr);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
        }
        OperationalLogFormat::Json => {
            let fmt_layer = fmt::layer().json().with_writer(std::io::stderr);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
        }
    }
}

/// Wait for a process shutdown signal so axum can drain in-flight requests cleanly.
async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!(signal = "ctrl-c", "received shutdown signal; draining"),
            Err(err) => error!(error = %err, "failed to install ctrl-c handler"),
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match install_sigterm_listener() {
            Ok(mut signal) => {
                signal.recv().await;
                info!(signal = "sigterm", "received shutdown signal; draining");
            }
            Err(err) => error!(error = %err, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(unix)]
fn install_sigterm_listener() -> io::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
}

#[cfg(test)]
mod tests {
    use super::{
        build_audit_sink, compile_relay_runtime, load_env_file_arg, parse_cli_command_from,
        parse_env_file_value, relay_config_value_classification, render_generated_api_key,
        run_audit_quarantine, run_healthcheck, url_contains_userinfo, CliCommand,
        ConfigValueClassification, GenerateApiKeyCommand, OperationalLogFormat, OutputFormat,
        DEFAULT_HEALTHCHECK_TIMEOUT_MS, DEFAULT_HEALTHCHECK_URL,
    };
    use axum::routing::get;
    use axum::Router;
    use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditChainHasher};
    use registry_platform_ops::DeploymentProfile;
    use registry_relay::audit::{AuditRecord, EndpointKind};
    use registry_relay::config::Config;
    use serde_json::{json, Value};
    use std::sync::{Mutex as StdMutex, OnceLock};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_listener_can_be_installed() {
        let _signal = super::install_sigterm_listener().expect("SIGTERM listener installs");
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| StdMutex::new(()))
            .lock()
            .expect("env lock")
    }

    fn sample_audit_record() -> AuditRecord {
        AuditRecord {
            ar_profile_id: None,
            ar_profile_version: None,
            ar_subject_id_type: None,
            ar_subject_id_hash: None,
            ar_requested_claims: None,
            ar_released_claims: None,
            ar_internal_outcome: None,
            ar_source_cardinality_outcome: None,
            ar_source_availability_class: None,
            ts: "2026-05-15T10:00:00.123Z".to_string(),
            request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            principal_id: Some("statistics_office".to_string()),
            auth_mode: Some("api_key".to_string()),
            remote_addr: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/v1/datasets".to_string(),
            endpoint_kind: EndpointKind::Catalog,
            dataset_id: None,
            entity_name: None,
            table_id: None,
            relationship: None,
            aggregate_id: None,
            underlying_kind: None,
            collection_id: None,
            primary_key: None,
            offering_id: None,
            verification_id: None,
            verification_decision: None,
            claim_hash: None,
            evidence_hash: None,
            pdp_policy_id: None,
            pdp_policy_hash: None,
            pdp_evaluated_rule_ids: None,
            pdp_stable_problem_code: None,
            pdp_ecosystem_binding_id: None,
            pdp_ecosystem_binding_version: None,
            pdp_route_identity: None,
            pdp_source_binding: None,
            pdp_checked_scopes: None,
            pdp_trust_provenance: None,
            scopes_used: vec!["catalog".to_string()],
            query_params: json!({}),
            purpose: Some("ci-smoke".to_string()),
            status_code: 200,
            row_count: None,
            null_geometry_count: None,
            invalid_geometry_count: None,
            geometry_vertex_count: None,
            suppressed_groups: None,
            duration_ms: 7,
            error_code: None,
            provenance: None,
            config: None,
        }
    }

    fn config_with_file_audit(path: &std::path::Path, hash_secret_env: &str) -> Config {
        serde_saphyr::from_str(&format!(
            r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: file
  path: '{}'
  hash_secret_env: {}
"#,
            path.display(),
            hash_secret_env
        ))
        .expect("test config parses")
    }

    fn runtime_config_yaml(hash_secret_env: &str) -> String {
        format!(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
  hash_secret_env: {hash_secret_env}
"#
        )
    }

    fn command_args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    async fn spawn_health_server(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let addr = listener.local_addr().expect("listener has local addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test health server serves");
        });
        format!("http://{addr}/healthz")
    }

    #[test]
    fn version_cli_parses_long_and_short_flags() {
        for flag in ["--version", "-V"] {
            let command = parse_cli_command_from(command_args(&["registry-relay", flag]))
                .expect("version command parses");

            assert_eq!(command, CliCommand::Version);
        }
    }

    #[test]
    fn version_cli_ignores_trailing_arguments() {
        // clap's built-in version flag short-circuits and ignores anything that
        // follows; the manual relay parser mirrors that behaviour.
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "--version",
            "--config",
            "config.yaml",
        ]))
        .expect("version command ignores trailing arguments");

        assert_eq!(command, CliCommand::Version);
    }

    #[test]
    fn healthcheck_cli_defaults_to_container_health_endpoint() {
        let command = parse_cli_command_from(command_args(&["registry-relay", "healthcheck"]))
            .expect("healthcheck command parses");

        let CliCommand::Healthcheck { url, timeout } = command else {
            panic!("expected healthcheck command");
        };
        assert_eq!(url, DEFAULT_HEALTHCHECK_URL);
        assert_eq!(
            timeout,
            Duration::from_millis(DEFAULT_HEALTHCHECK_TIMEOUT_MS)
        );
    }

    #[test]
    fn healthcheck_cli_accepts_url_and_timeout_overrides() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "healthcheck",
            "--url",
            "http://127.0.0.1:9090/healthz",
            "--timeout-ms=250",
        ]))
        .expect("healthcheck command parses");

        let CliCommand::Healthcheck { url, timeout } = command else {
            panic!("expected healthcheck command");
        };
        assert_eq!(url, "http://127.0.0.1:9090/healthz");
        assert_eq!(timeout, Duration::from_millis(250));
    }

    #[test]
    fn healthcheck_cli_accepts_equals_url_and_split_timeout_overrides() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "healthcheck",
            "--url=http://127.0.0.1:9091/healthz",
            "--timeout-ms",
            "750",
        ]))
        .expect("healthcheck command parses");

        let CliCommand::Healthcheck { url, timeout } = command else {
            panic!("expected healthcheck command");
        };
        assert_eq!(url, "http://127.0.0.1:9091/healthz");
        assert_eq!(timeout, Duration::from_millis(750));
    }

    #[test]
    fn openapi_cli_accepts_config_and_env_file() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "openapi",
            "--config",
            "openapi/registry-relay.reference.yaml",
            "--env-file=/etc/registry-relay/openapi.env",
        ]))
        .expect("openapi command parses");

        let CliCommand::Openapi {
            config_path,
            env_file,
        } = command
        else {
            panic!("expected openapi command");
        };
        assert_eq!(
            config_path,
            std::path::PathBuf::from("openapi/registry-relay.reference.yaml")
        );
        assert_eq!(
            env_file,
            Some(std::path::PathBuf::from("/etc/registry-relay/openapi.env"))
        );
    }

    #[test]
    fn openapi_cli_rejects_serve_only_arguments() {
        let err = parse_cli_command_from(command_args(&[
            "registry-relay",
            "openapi",
            "--bind",
            "127.0.0.1:9090",
        ]))
        .expect_err("openapi command rejects serve-only flag");

        assert_eq!(err.to_string(), "unknown openapi argument: --bind");
    }

    #[test]
    fn doctor_cli_accepts_config_env_file_and_json_format() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "doctor",
            "--config",
            "/etc/registry-relay/config.yaml",
            "--env-file=/etc/registry-relay/relay.env",
            "--format",
            "json",
        ]))
        .expect("doctor command parses");

        let CliCommand::Doctor {
            config_path,
            env_file,
            format,
            profile_override,
        } = command
        else {
            panic!("expected doctor command");
        };
        assert_eq!(
            config_path,
            std::path::PathBuf::from("/etc/registry-relay/config.yaml")
        );
        assert_eq!(
            env_file,
            Some(std::path::PathBuf::from("/etc/registry-relay/relay.env"))
        );
        assert_eq!(format, OutputFormat::Json);
        assert!(profile_override.is_none());
    }

    #[test]
    fn doctor_cli_defaults_env_file_from_env_format_to_json_and_accepts_profile() {
        let _guard = env_lock();
        std::env::set_var("REGISTRY_RELAY_ENV_FILE", "/etc/registry-relay/default.env");

        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "doctor",
            "--config=/etc/registry-relay/config.yaml",
            "--profile",
            "local",
        ]))
        .expect("doctor command parses");

        let CliCommand::Doctor {
            env_file,
            format,
            profile_override,
            ..
        } = command
        else {
            panic!("expected doctor command");
        };
        assert_eq!(
            env_file,
            Some(std::path::PathBuf::from("/etc/registry-relay/default.env"))
        );
        assert_eq!(format, OutputFormat::Json);
        assert_eq!(profile_override, Some(DeploymentProfile::Local));

        std::env::remove_var("REGISTRY_RELAY_ENV_FILE");
    }

    #[test]
    fn doctor_cli_rejects_unknown_format() {
        let err = parse_cli_command_from(command_args(&[
            "registry-relay",
            "doctor",
            "--format",
            "text",
        ]))
        .expect_err("doctor rejects unsupported format");

        assert_eq!(err.to_string(), "--format must be json");
    }

    #[test]
    fn doctor_cli_rejects_unknown_profile() {
        let err = parse_cli_command_from(command_args(&[
            "registry-relay",
            "doctor",
            "--profile",
            "pilot",
        ]))
        .expect_err("doctor rejects unsupported deployment profile");

        assert_eq!(
            err.to_string(),
            "--profile must be local, hosted_lab, production, or evidence_grade"
        );
    }

    #[test]
    fn schema_cli_accepts_json_format() {
        let command =
            parse_cli_command_from(command_args(&["registry-relay", "schema", "--format=json"]))
                .expect("schema command parses");

        let CliCommand::Schema { format } = command else {
            panic!("expected schema command");
        };
        assert_eq!(format, OutputFormat::Json);
    }

    #[test]
    fn schema_cli_rejects_unknown_format() {
        let err = parse_cli_command_from(command_args(&[
            "registry-relay",
            "schema",
            "--format",
            "text",
        ]))
        .expect_err("schema rejects unsupported format");

        assert_eq!(err.to_string(), "--format must be json");
    }

    #[test]
    fn serve_cli_preserves_config_flag_parsing() {
        let _guard = env_lock();
        let previous_env_file = std::env::var_os("REGISTRY_RELAY_ENV_FILE");
        std::env::remove_var("REGISTRY_RELAY_ENV_FILE");

        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "--config",
            "/etc/registry-relay/config.yaml",
        ]))
        .expect("serve command parses");

        let CliCommand::Serve {
            config_path,
            env_file,
            bind_override,
            ..
        } = command
        else {
            panic!("expected serve command");
        };
        assert_eq!(
            config_path,
            std::path::PathBuf::from("/etc/registry-relay/config.yaml")
        );
        assert!(env_file.is_none());
        assert!(bind_override.is_none());

        if let Some(value) = previous_env_file {
            std::env::set_var("REGISTRY_RELAY_ENV_FILE", value);
        }
    }

    #[test]
    fn serve_cli_accepts_env_file_and_bind_override() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "--config=/etc/registry-relay/config.yaml",
            "--env-file",
            "/etc/registry-relay/relay.env",
            "--bind=127.0.0.1:9090",
        ]))
        .expect("serve command parses");

        let CliCommand::Serve {
            config_path,
            env_file,
            bind_override,
            ..
        } = command
        else {
            panic!("expected serve command");
        };
        assert_eq!(
            config_path,
            std::path::PathBuf::from("/etc/registry-relay/config.yaml")
        );
        assert_eq!(
            env_file,
            Some(std::path::PathBuf::from("/etc/registry-relay/relay.env"))
        );
        assert_eq!(
            bind_override,
            Some("127.0.0.1:9090".parse().expect("socket address parses"))
        );
    }

    #[test]
    fn serve_cli_reads_bind_and_env_file_from_env() {
        let _guard = env_lock();
        std::env::set_var("REGISTRY_RELAY_BIND", "127.0.0.1:9191");
        std::env::set_var("REGISTRY_RELAY_ENV_FILE", "/etc/registry-relay/relay.env");

        let command = parse_cli_command_from(command_args(&["registry-relay"]))
            .expect("serve command parses");

        let CliCommand::Serve {
            env_file,
            bind_override,
            ..
        } = command
        else {
            panic!("expected serve command");
        };
        assert_eq!(
            env_file,
            Some(std::path::PathBuf::from("/etc/registry-relay/relay.env"))
        );
        assert_eq!(
            bind_override,
            Some("127.0.0.1:9191".parse().expect("socket address parses"))
        );

        std::env::remove_var("REGISTRY_RELAY_BIND");
        std::env::remove_var("REGISTRY_RELAY_ENV_FILE");
    }

    #[test]
    fn generate_api_key_cli_accepts_id() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "generate-api-key",
            "--id=operator_reader",
        ]))
        .expect("generate command parses");

        assert_eq!(
            command,
            CliCommand::GenerateApiKey(GenerateApiKeyCommand {
                id: "operator_reader".to_string()
            })
        );
    }

    #[test]
    fn generate_api_key_cli_rejects_invalid_id() {
        let err = parse_cli_command_from(command_args(&[
            "registry-relay",
            "generate-api-key",
            "--id",
            "OperatorReader",
        ]))
        .expect_err("uppercase id rejected");

        assert_eq!(err.to_string(), "--id requires a lower-snake API key id");
    }

    #[test]
    fn generated_api_key_output_contains_fingerprint_without_commitment() {
        let output = render_generated_api_key("operator_reader", &[7_u8; 32]);

        assert!(output.contains("api_key_id=operator_reader\n"));
        assert!(output.contains("api_key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\n"));
        assert!(output.contains("fingerprint=sha256:"));
        assert!(!output.contains("commitment="));
    }

    #[test]
    fn env_file_loads_values_without_overwriting_process_env() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        let env_file = dir.path().join("relay.env");
        std::fs::write(
            &env_file,
            "REGISTRY_RELAY_TEST_ENV_FILE_TOKEN=file-token\nREGISTRY_RELAY_TEST_ENV_FILE_KEEP=file-value\n",
        )
        .expect("env file writes");
        std::env::set_var("REGISTRY_RELAY_TEST_ENV_FILE_KEEP", "process-value");
        std::env::remove_var("REGISTRY_RELAY_TEST_ENV_FILE_TOKEN");

        load_env_file_arg(Some(&env_file)).expect("env file loads");

        assert_eq!(
            std::env::var("REGISTRY_RELAY_TEST_ENV_FILE_TOKEN").expect("token set"),
            "file-token"
        );
        assert_eq!(
            std::env::var("REGISTRY_RELAY_TEST_ENV_FILE_KEEP").expect("existing value kept"),
            "process-value"
        );

        std::env::remove_var("REGISTRY_RELAY_TEST_ENV_FILE_TOKEN");
        std::env::remove_var("REGISTRY_RELAY_TEST_ENV_FILE_KEEP");
    }

    #[test]
    fn env_file_value_parser_handles_single_quote_values() {
        assert_eq!(parse_env_file_value("\""), "\"");
        assert_eq!(parse_env_file_value("'"), "'");
    }

    #[test]
    fn config_explanation_redacts_private_and_passphrase_keys() {
        for key in [
            "private_key",
            "privatekey",
            "private_jwk",
            "signing_passphrase",
            "passphrase",
        ] {
            assert_eq!(
                relay_config_value_classification(&["provenance", key], &json!("sensitive")),
                ConfigValueClassification::Secret,
                "{key} should be classified as secret"
            );
        }
    }

    #[test]
    fn config_explanation_redacts_url_with_userinfo_under_non_secret_key() {
        // M-1: a URL carrying basic-auth credentials must be redacted even when
        // the key name is not a trigger word on its own.
        for (path, value) in [
            (
                vec!["auth", "oidc", "jwks_url"],
                "https://svc:s3cr3t@idp.example.com/.well-known/jwks.json",
            ),
            (
                vec!["catalog", "endpoint"],
                "https://user@host.example.com/path",
            ),
            (
                vec!["datasets", "source"],
                "postgres://app:hunter2@db.internal:5432/registry",
            ),
        ] {
            let path: Vec<&str> = path;
            assert_eq!(
                relay_config_value_classification(&path, &json!(value)),
                ConfigValueClassification::Secret,
                "{value:?} under {path:?} should be redacted (URL userinfo)"
            );
        }
    }

    #[test]
    fn config_explanation_keeps_plain_non_secret_values_public() {
        // Plain values, and URLs without userinfo under non-secret keys, must
        // not be over-redacted. Bare `@` (emails) is not a URL userinfo leak.
        for (path, value) in [
            (vec!["catalog", "title"], "Test Catalog"),
            (vec!["server", "bind"], "0.0.0.0:8080"),
            (vec!["catalog", "contact"], "ops@example.com"),
        ] {
            let path: Vec<&str> = path;
            assert_eq!(
                relay_config_value_classification(&path, &json!(value)),
                ConfigValueClassification::Public,
                "{value:?} under {path:?} should stay public"
            );
        }
    }

    #[test]
    fn config_explanation_keeps_public_key_material_public() {
        // The broad `key` substring match must not redact well-known public
        // key material or key identifiers.
        for key in ["public_key", "pubkey", "kid", "key_id", "signer_public_key"] {
            assert_eq!(
                relay_config_value_classification(&["provenance", key], &json!("MFkwEw...")),
                ConfigValueClassification::Public,
                "{key} should stay public"
            );
        }
    }

    #[test]
    fn config_explanation_redacts_broadened_secret_keys() {
        // Existing secret-keyed leaves remain redacted, and the broadened set
        // (url/uri/dsn/connection/credential/*key*) is now redacted too.
        for key in [
            "api_secret",
            "auth_token",
            "jwks_url",
            "callback_uri",
            "database_dsn",
            "connection_string",
            "service_credential",
            "apikey",
            "signing_key",
            "private_public_key",
            "public_key_secret",
        ] {
            assert_eq!(
                relay_config_value_classification(&["section", key], &json!("value")),
                ConfigValueClassification::Secret,
                "{key} should be classified as secret"
            );
        }
    }

    #[test]
    fn url_userinfo_detection_avoids_false_positives() {
        assert!(url_contains_userinfo(
            "https://user:pass@host.example.com/path"
        ));
        assert!(url_contains_userinfo("https://user@host.example.com"));
        assert!(url_contains_userinfo("  redis://default:pw@cache:6379/0  "));
        // No scheme: a bare email is not a URL userinfo leak.
        assert!(!url_contains_userinfo("ops@example.com"));
        // `@` only in the path/query, not the authority.
        assert!(!url_contains_userinfo("https://host.example.com/u@v"));
        assert!(!url_contains_userinfo("https://host.example.com/?q=a@b"));
        // Plain URL without userinfo.
        assert!(!url_contains_userinfo("https://host.example.com/path"));
        // Not a URL at all.
        assert!(!url_contains_userinfo("just a string"));
        assert!(!url_contains_userinfo("://malformed@host"));
    }

    #[test]
    fn config_verify_bundle_cli_accepts_bundle_flags() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "config",
            "verify-bundle",
            "--bundle-dir",
            "/etc/registry-relay/bundle",
            "--anchor-path=/etc/registry-relay/trust_anchor.json",
            "--state-path",
            "/var/lib/registry-relay/config-state/antirollback.json",
        ]))
        .expect("config verify-bundle command parses");

        let CliCommand::ConfigVerifyBundle(command) = command else {
            panic!("expected config verify-bundle command");
        };
        assert_eq!(
            command.bundle_dir,
            std::path::PathBuf::from("/etc/registry-relay/bundle")
        );
        assert_eq!(
            command.anchor_path,
            std::path::PathBuf::from("/etc/registry-relay/trust_anchor.json")
        );
        assert_eq!(
            command.state_path,
            std::path::PathBuf::from("/var/lib/registry-relay/config-state/antirollback.json")
        );
    }

    #[test]
    fn config_apply_bundle_cli_is_no_longer_supported() {
        let err =
            parse_cli_command_from(command_args(&["registry-relay", "config", "apply-bundle"]))
                .expect_err("config apply-bundle is removed");

        assert_eq!(
            err.to_string(),
            "config apply-bundle is no longer supported by registry-relay"
        );
    }

    #[test]
    fn config_verify_bundle_cli_requires_state_path() {
        let err = parse_cli_command_from(command_args(&[
            "registry-relay",
            "config",
            "verify-bundle",
            "--bundle-dir",
            "/etc/registry-relay/bundle",
            "--anchor-path",
            "/etc/registry-relay/trust_anchor.json",
        ]))
        .expect_err("state path is required");

        assert_eq!(err.to_string(), "missing required flag --state-path");
    }

    #[test]
    fn config_cli_rejects_unknown_subcommand() {
        let err = parse_cli_command_from(command_args(&["registry-relay", "config", "reload"]))
            .expect_err("unknown config subcommand fails");

        assert_eq!(err.to_string(), "unknown config subcommand: reload");
    }

    #[tokio::test]
    async fn healthcheck_succeeds_for_success_status() {
        let url = spawn_health_server(
            Router::new().route("/healthz", get(|| async { axum::http::StatusCode::OK })),
        )
        .await;

        run_healthcheck(&url, Duration::from_secs(1))
            .await
            .expect("healthcheck succeeds");
    }

    #[tokio::test]
    async fn healthcheck_fails_for_non_success_status() {
        let url = spawn_health_server(Router::new().route(
            "/healthz",
            get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
        ))
        .await;

        let err = run_healthcheck(&url, Duration::from_secs(1))
            .await
            .expect_err("healthcheck fails");
        assert!(
            err.to_string().contains("status 503"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn healthcheck_fails_for_connection_failure() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let addr = listener.local_addr().expect("listener has local addr");
        drop(listener);
        let url = format!("http://{addr}/healthz");

        let err = run_healthcheck(&url, Duration::from_millis(200))
            .await
            .expect_err("healthcheck fails");
        assert!(
            err.to_string().contains("request failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn healthcheck_fails_for_timeout() {
        let url = spawn_health_server(Router::new().route(
            "/healthz",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                axum::http::StatusCode::OK
            }),
        ))
        .await;

        let err = run_healthcheck(&url, Duration::from_millis(10))
            .await
            .expect_err("healthcheck fails");
        assert!(
            err.to_string().contains("request failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn compile_relay_runtime_is_named_fail_closed_boundary() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("relay.yaml");
        let env_name = "REGISTRY_RELAY_TEST_COMPILE_MISSING_AUDIT_HASH";
        std::env::remove_var(env_name);
        std::fs::write(&config_path, runtime_config_yaml(env_name)).expect("config writes");

        let err = match compile_relay_runtime(config_path, None).await {
            Ok(_) => panic!("missing audit secret should fail compile"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("missing")
                || err.to_string().contains("Missing")
                || err.to_string().contains("validation"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn compile_relay_runtime_refuses_undeclared_deployment_profile() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("relay.yaml");
        let yaml = runtime_config_yaml("REGISTRY_RELAY_TEST_COMPILE_PROFILE_AUDIT_HASH")
            .replacen("deployment:\n  profile: local\n", "", 1)
            .replacen(
                "  hash_secret_env: REGISTRY_RELAY_TEST_COMPILE_PROFILE_AUDIT_HASH\n",
                "",
                1,
            );
        std::fs::write(&config_path, yaml).expect("config writes");

        let err = match compile_relay_runtime(config_path, None).await {
            Ok(_) => panic!("undeclared deployment profile should fail compile"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("set deployment.profile: local for development"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compile_relay_runtime_does_not_start_ingest_or_refresh_tasks() {
        let source = include_str!("main.rs");
        let compile_body = source
            .split("async fn compile_relay_runtime")
            .nth(1)
            .and_then(|tail| tail.split("fn build_relay_app_from_runtime").next())
            .expect("compile_relay_runtime body is present");

        assert!(
            !compile_body.contains("run_initial_ingest"),
            "compile boundary must not perform initial ingest side effects"
        );
        assert!(
            !compile_body.contains("spawn_refresh_tasks"),
            "compile boundary must not start background refresh tasks"
        );
    }

    #[test]
    fn operational_log_format_defaults_to_text_for_empty_or_unknown_values() {
        assert_eq!(OperationalLogFormat::parse(""), OperationalLogFormat::Text);
        assert_eq!(
            OperationalLogFormat::parse("text"),
            OperationalLogFormat::Text
        );
        assert_eq!(
            OperationalLogFormat::parse("compact"),
            OperationalLogFormat::Text
        );
        assert_eq!(
            OperationalLogFormat::parse("xml"),
            OperationalLogFormat::Text
        );
    }

    #[test]
    fn operational_log_format_accepts_json_aliases() {
        assert_eq!(
            OperationalLogFormat::parse("json"),
            OperationalLogFormat::Json
        );
        assert_eq!(
            OperationalLogFormat::parse(" JSONL "),
            OperationalLogFormat::Json
        );
    }

    #[tokio::test]
    async fn build_audit_sink_uses_configured_hash_secret_for_chain() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let env_name = "REGISTRY_RELAY_TEST_AUDIT_CHAIN_SECRET";
        std::env::set_var(env_name, "0123456789abcdef0123456789abcdef");
        let config = config_with_file_audit(&path, env_name);

        let sink = build_audit_sink(&config).expect("audit sink builds");
        sink.write_record(sample_audit_record())
            .await
            .expect("audit record writes");
        sink.flush().await.expect("audit sink flushes");

        let contents = std::fs::read_to_string(&path).expect("audit file was written");
        assert!(
            verify_jsonl_lines_with_hasher(contents.lines(), &AuditChainHasher::unkeyed_dev_only())
                .is_err(),
            "runtime audit chain must not verify with the dev-only unkeyed hasher"
        );
        let hasher =
            AuditChainHasher::from_env_derived(env_name).expect("audit chain secret loads");
        verify_jsonl_lines_with_hasher(contents.lines(), &hasher)
            .expect("audit chain verifies with configured secret");
    }

    fn file_audit_config_yaml(path: &std::path::Path, hash_secret_env: &str) -> String {
        format!(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: file
  path: '{}'
  hash_secret_env: {}
"#,
            path.display(),
            hash_secret_env
        )
    }

    #[test]
    fn parses_audit_quarantine_command() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "audit",
            "quarantine",
            "--config",
            "/etc/relay.yaml",
            "--reason",
            "unclean stop",
            "--operator",
            "jeremi",
        ]))
        .expect("audit quarantine parses");
        match command {
            CliCommand::AuditQuarantine {
                config_path,
                reason,
                operator,
                ..
            } => {
                assert_eq!(config_path, std::path::PathBuf::from("/etc/relay.yaml"));
                assert_eq!(reason, "unclean stop");
                assert_eq!(operator.as_deref(), Some("jeremi"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn audit_quarantine_requires_a_reason() {
        let error = parse_cli_command_from(command_args(&[
            "registry-relay",
            "audit",
            "quarantine",
            "--config",
            "/etc/relay.yaml",
        ]))
        .expect_err("missing reason is rejected");
        assert!(
            error.to_string().contains("--reason"),
            "error should name the missing flag: {error}"
        );
    }

    #[tokio::test]
    async fn audit_quarantine_recovers_a_tampered_chain_end_to_end() {
        let dir = tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let env_name = "REGISTRY_RELAY_TEST_QUARANTINE_E2E_SECRET";
        std::env::set_var(env_name, "0123456789abcdef0123456789abcdef");
        let config = config_with_file_audit(&audit_path, env_name);

        // Write a valid keyed chain, then release the single-writer lock (the
        // relay has exited) and tamper the second record so the chain no longer
        // verifies under the configured secret.
        let sink = build_audit_sink(&config).expect("audit sink builds");
        sink.write_record(sample_audit_record())
            .await
            .expect("first write");
        sink.write_record(sample_audit_record())
            .await
            .expect("second write");
        drop(sink);

        let original = std::fs::read_to_string(&audit_path).expect("audit file");
        let mut lines: Vec<String> = original.lines().map(String::from).collect();
        assert_eq!(lines.len(), 2);
        lines[1] = lines[1].replace("statistics_office", "tampered_office");
        std::fs::write(&audit_path, format!("{}\n", lines.join("\n"))).expect("tamper write");

        let config_path = dir.path().join("relay.yaml");
        std::fs::write(&config_path, file_audit_config_yaml(&audit_path, env_name))
            .expect("write config file");
        run_audit_quarantine(
            config_path,
            None,
            "unit tamper recovery".to_string(),
            Some("ci".to_string()),
        )
        .await
        .expect("quarantine runs");

        let archive_count = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("audit.jsonl.corrupt-")
            })
            .count();
        assert_eq!(archive_count, 1, "the corrupt chain must be quarantined");

        let recovered = std::fs::read_to_string(&audit_path).expect("recovered active file");
        let recovered_lines: Vec<&str> = recovered.lines().collect();
        assert_eq!(recovered_lines.len(), 1);
        let break_envelope: Value =
            serde_json::from_str(recovered_lines[0]).expect("break envelope parses");
        assert_eq!(break_envelope["record"]["event"], "audit.chain.break");

        // The anchor pins the recovered segment's start to the break event's
        // predecessor (the last good tail).
        let anchor: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("audit.jsonl.anchor.json"))
                .expect("anchor file"),
        )
        .expect("anchor json");
        assert_eq!(
            anchor["trusted_start_prev_hash"],
            break_envelope["prev_hash"]
        );
    }
}
