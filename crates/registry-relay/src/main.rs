// SPDX-License-Identifier: Apache-2.0
//! registry-relay binary entry point.
//!
//! Wires the V1 gateway into a runnable HTTP server:
//! 1. Initialise operational tracing on stderr.
//! 2. Load and validate either a local YAML config selected by `--config
//!    <path>`, `REGISTRY_RELAY_CONFIG`, or `./config/example.yaml` (in that
//!    order of precedence), or a verified signed bundle selected by the
//!    complete `--bundle-dir`, `--anchor-path`, and `--state-path` flag set.
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
//! `main` returns a non-zero process exit on failure. Before a failure crosses
//! the default stderr/tracing boundary, it is reduced to a product-owned
//! [`registry_relay::process_startup`] code with static meaning and
//! remediation. Inner errors and runtime values are never rendered there.

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
use registry_platform_config::{
    expand_config_env_vars, load_anchor_transition, load_trust_anchor, sha256_uri,
    verify_config_bundle, ProductTrustDomainV1,
};
use registry_platform_ops::{
    audit_shipping_target, bundle_verify_rejection_code, internal_config_hash,
    persist_bundle_acceptance as persist_config_bundle_acceptance, AcceptanceAuditIntentV1,
    AcceptanceMutationKindV1, AcceptanceStatePreviewV1, AntiRollbackStoreError, ApplyReportResult,
    AuditSinkKind, BundleVerificationCode, ConfigOverrideMode, ConfigSource, DeploymentProfile,
    FileAntiRollbackStore, VerifiedAcceptanceStateV1,
};
use registry_relay::audit::{
    AuditPipeline, ConfigAuditExt, FileSink, OperationalAuditEvent, StdoutSink, SyslogSink,
};
use registry_relay::auth::middleware::{AuthProviderRef, RuntimeAuthProvider};
use registry_relay::auth::runtime::build_auth;
use registry_relay::config::{self, AuditSinkConfig, Config, SourceConfig};
use registry_relay::consultation::operator::{
    initialize_state_from_signed_policy, prepare_state_store_from_signed_policy,
};
use registry_relay::consultation::{
    ConsultationService, ConsultationServiceActivationError, ConsultationServiceActivationFailure,
};
use registry_relay::entity::EntityRegistry;
use registry_relay::error::{ConfigError, Error};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot};
use registry_relay::observability::RequestMetrics;
use registry_relay::process_startup::{
    emit_process_startup_failure, ProcessStartupCode, ProcessStartupFailure,
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
use tracing::instrument::WithSubscriber;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use ulid::Ulid;

/// CLI flag for the config path. Kept minimal: a single `--config
/// <path>` positional plus the `REGISTRY_RELAY_CONFIG` env var fallback.
const CONFIG_FLAG: &str = "--config";
const ENV_FILE_FLAG: &str = "--env-file";
const BIND_FLAG: &str = "--bind";
const ID_FLAG: &str = "--id";
const PLAN_FLAG: &str = "--plan";

/// Top-level command for shell-free container liveness probing.
const HEALTHCHECK_COMMAND: &str = "healthcheck";

/// Generates a standalone API key and canonical fingerprint.
const GENERATE_API_KEY_COMMAND: &str = "generate-api-key";

/// Top-level command for generating the OpenAPI release artifact.
const OPENAPI_COMMAND: &str = "openapi";

/// Internal fixed-purpose development source. Registryctl is its only
/// supported caller and supplies one compiler-owned closed plan.
const SYNTHETIC_SOURCE_COMMAND: &str = "synthetic-source";
const SYNTHETIC_SOURCE_PROBE_ACTION: &str = "probe";

/// Offline operator diagnostics for config, env, and metadata readiness.
const DOCTOR_COMMAND: &str = "doctor";

/// Prints a redacted resolved configuration explanation.
const EXPLAIN_CONFIG_COMMAND: &str = "explain-config";

/// Prints the complete product-owned Relay runtime configuration schema.
const SCHEMA_COMMAND: &str = "schema";

/// Top-level namespace for operator configuration commands.
const CONFIG_COMMAND: &str = "config";

/// Exact product-owned runtime interface consumed by the signed release lock.
const PRODUCT_ACTION_COMMAND: &str = "product-action";
const DEVELOPMENT_ACTION_COMMAND: &str = "development-action";
const PREPARE_STATE_STORE_ACTION: &str = "prepare_state_store";
const INITIALIZE_STATE_ACTION: &str = "initialize_state";
const PREVIEW_STATE_ACTION: &str = "preview_state";
const ACCEPT_STATE_ACTION: &str = "accept_state";
const VERIFY_STATE_ACTION: &str = "verify_state";
const SERVE_ACTION: &str = "serve";
const PRODUCT_BUNDLE_PATH: &str = "/run/registry/bundle";
const PRODUCT_ANCHOR_PATH: &str = "/run/registry/anchor/anchor.json";
const PRODUCT_PREVIOUS_ANCHOR_PATH: &str = "/run/registry/anchor/previous-anchor.json";
const PRODUCT_ANCHOR_TRANSITION_PATH: &str = "/run/registry/anchor/transition.json";
const PRODUCT_ANTIROLLBACK_STATE_PATH: &str = "/var/lib/registry/state/antirollback.json";

/// Audit operator tooling command and its offline chain-recovery subcommand.
const AUDIT_COMMAND: &str = "audit";
const QUARANTINE_SUBCOMMAND: &str = "quarantine";
const REASON_FLAG: &str = "--reason";
const OPERATOR_FLAG: &str = "--operator";

/// Retired raw consultation operator namespace.
const CONSULTATION_COMMAND: &str = "consultation";

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
const EXPECTED_CONFIG_DIGEST_FLAG: &str = "--expected-config-digest";
const RELAY_CONFIG_SCHEMA_VERSION: &str = "registry.relay.config.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Version,
    Serve {
        config_source: ServeConfigSource,
        env_file: Option<PathBuf>,
        bind_override: Option<SocketAddr>,
    },
    ProductAction(ProductActionCommand),
    DevelopmentAction(ProductActionCommand),
    Healthcheck {
        url: String,
        timeout: Duration,
    },
    GenerateApiKey(GenerateApiKeyCommand),
    Openapi {
        config_path: PathBuf,
        env_file: Option<PathBuf>,
    },
    SyntheticSource(SyntheticSourceCommand),
    Doctor {
        config_path: PathBuf,
        env_file: Option<PathBuf>,
        format: OutputFormat,
        profile_override: Option<DeploymentProfile>,
        expected_config_digest: Option<ExpectedConfigDigest>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum SyntheticSourceCommand {
    Serve { plan_path: PathBuf },
    Probe { plan_path: PathBuf },
}

#[derive(Clone, PartialEq, Eq)]
enum ServeConfigSource {
    LocalFile {
        config_path: PathBuf,
    },
    SignedBundle {
        bundle_dir: PathBuf,
        anchor_path: PathBuf,
        state_path: PathBuf,
        expected_lane: Option<config::loader::RelayProductLane>,
    },
}

impl std_fmt::Debug for ServeConfigSource {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        match self {
            Self::LocalFile { .. } => formatter
                .debug_struct("LocalFile")
                .field("config_path", &"<configured>")
                .finish(),
            Self::SignedBundle { .. } => formatter
                .debug_struct("SignedBundle")
                .field("bundle_dir", &"<configured>")
                .field("anchor_path", &"<configured>")
                .field("state_path", &"<configured>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProductActionCommand {
    lane: config::loader::RelayProductLane,
    action: ProductAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductAction {
    PrepareStateStore,
    InitializeState,
    PreviewState,
    AcceptState,
    VerifyState,
    Serve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GenerateApiKeyCommand {
    id: String,
}

#[derive(Clone, PartialEq, Eq)]
struct ExpectedConfigDigest(String);

impl ExpectedConfigDigest {
    fn parse(value: &str) -> Result<Self, CliError> {
        let Some(digest) = value.strip_prefix("sha256:") else {
            return Err(CliError(format!(
                "{EXPECTED_CONFIG_DIGEST_FLAG} requires a sha256 digest"
            )));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CliError(format!(
                "{EXPECTED_CONFIG_DIGEST_FLAG} requires a sha256 digest"
            )));
        }
        Ok(Self(value.to_string()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std_fmt::Debug for ExpectedConfigDigest {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        formatter.write_str("ExpectedConfigDigest(<configured>)")
    }
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

/// Marker for a configuration-loader error whose stable process diagnostic was
/// emitted by the loader before it returned.
///
/// The loader owns the detailed classification because it can distinguish
/// source, document, validation, bundle, metadata, and consultation failures.
/// Keeping this marker value-free prevents `main` from adding a second,
/// generic startup code or exposing the source error.
#[derive(Debug)]
struct ReportedConfigLoadFailure;

impl std_fmt::Display for ReportedConfigLoadFailure {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        formatter.write_str("configuration load failure was already reported")
    }
}

impl StdError for ReportedConfigLoadFailure {}

fn reported_config_load<T>(result: Result<T, Error>) -> Result<T, ReportedConfigLoadFailure> {
    result.map_err(|_| ReportedConfigLoadFailure)
}

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

fn main() -> ExitCode {
    if registry_relay::rhai_worker::is_worker_invocation(env::args_os()) {
        return registry_relay::rhai_worker::run_worker_stdio();
    }

    async_main()
}

#[tokio::main]
async fn async_main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if let Some(failure) = err.downcast_ref::<OperatorSafeConsultationActivationFailure>() {
                failure.emit();
            } else if err.downcast_ref::<ReportedConfigLoadFailure>().is_none() {
                let failure = err
                    .downcast_ref::<ProcessStartupFailure>()
                    .copied()
                    .unwrap_or_else(|| {
                        ProcessStartupFailure::new(
                            ProcessStartupCode::RUNTIME_INITIALIZATION_FAILED,
                        )
                    });
                emit_process_startup_failure(failure.code());
            }
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match parse_cli_command_from(env::args().collect())? {
        CliCommand::Version => {
            println!(
                "{} {}",
                env!("CARGO_PKG_NAME"),
                registry_platform_buildinfo::DISPLAY_VERSION
            );
            Ok(())
        }
        CliCommand::Serve {
            config_source,
            env_file,
            bind_override,
        } => run_server(config_source, env_file, bind_override, None).await,
        CliCommand::ProductAction(command) => {
            run_product_action(command, ProductTrustDomainV1::Governed).await
        }
        CliCommand::DevelopmentAction(command) => {
            run_product_action(command, ProductTrustDomainV1::Development).await
        }
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
        CliCommand::SyntheticSource(SyntheticSourceCommand::Serve { plan_path }) => {
            registry_relay::synthetic_source::run(&plan_path).await?;
            Ok(())
        }
        CliCommand::SyntheticSource(SyntheticSourceCommand::Probe { plan_path }) => {
            println!(
                "{}",
                registry_relay::synthetic_source::probe(&plan_path).await?
            );
            Ok(())
        }
        CliCommand::Doctor {
            config_path,
            env_file,
            format,
            profile_override,
            expected_config_digest,
        } => {
            run_doctor(
                config_path,
                env_file,
                format,
                profile_override,
                expected_config_digest,
            )
            .await
        }
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
    config_source: ServeConfigSource,
    env_file: Option<PathBuf>,
    bind_override: Option<SocketAddr>,
    verified_product_input: Option<config::loader::VerifiedProductActionInput>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    load_env_file_arg(env_file.as_deref())?;
    if (matches!(&config_source, ServeConfigSource::SignedBundle { .. })
        || verified_product_input.is_some())
        && config_path_env_is_set()
    {
        return Err(Box::new(CliError(
            "local config cannot be combined with signed-bundle serve flags".to_string(),
        )));
    }
    let handle = Arc::new(RelayRuntimeHandle::new(match verified_product_input {
        Some(input) => {
            compile_loaded_relay_runtime(input.into_loaded_config(), bind_override).await?
        }
        None => {
            compile_relay_runtime_with_options(
                config_source,
                bind_override,
                config::LoadOptions::default(),
            )
            .await?
        }
    }));
    let runtime = handle.load_full();
    let app = build_relay_app_from_runtime(Arc::clone(&handle))?;

    let listener = TcpListener::bind(runtime.bind).await.map_err(|error| {
        ProcessStartupFailure::new(ProcessStartupCode::from_data_listener_bind(error.kind()))
    })?;

    let admin_listener = match runtime.admin_bind {
        Some(addr) => Some(TcpListener::bind(addr).await.map_err(|error| {
            ProcessStartupFailure::new(ProcessStartupCode::from_admin_listener_bind(error.kind()))
        })?),
        None => None,
    };

    // Do not render either configured binding before both requested listeners
    // have opened successfully. A bind failure crosses the value-free process
    // diagnostic boundary and must not inherit the other listener's address
    // from a preceding informational event.
    info!(
        bind = %runtime.bind,
        admin_bind = ?runtime.admin_bind,
        datasets = runtime.dataset_count(),
        api_keys = runtime.auth_size_hint(),
        audit_sink = runtime.audit_kind,
        consultation_enabled = runtime.consultation.is_some(),
        "registry-relay listening"
    );

    let serve_limits = ServeLimits::from_config(&runtime.config.server);
    let admin_app = if admin_listener.is_some() {
        let auth: AuthProviderRef = Arc::new(RuntimeAuthProvider::new(Arc::clone(&handle)));
        Some(
            registry_relay::server::build_admin_app_with_metadata_and_metrics(
                Arc::clone(&runtime.config),
                auth,
                Arc::clone(&runtime.audit_sink),
                runtime.readiness_rx.clone(),
                runtime.readiness_tx.clone(),
                Arc::clone(&runtime.ingest),
                runtime.compiled_metadata.clone(),
                Arc::clone(&runtime.metrics),
            )?
            .layer(Extension(Arc::clone(&handle))),
        )
    } else {
        None
    };

    if let Some(acceptance) = runtime.pending_bundle_acceptance.as_ref() {
        write_boot_config_audits(&runtime.audit_sink, acceptance).await?;
        persist_bundle_acceptance(acceptance)?;
    }
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

    // Run both servers concurrently. `tokio::select!` is the natural
    // fit because either listener exiting (clean or not) tears down
    // the other.
    let main_serve = serve_listener(listener, app, serve_limits, shutdown_signal());
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        if let Some(admin_listener) = admin_listener {
            let admin_app = admin_app.expect("admin app is built when admin listener is present");
            let admin_serve =
                serve_listener(admin_listener, admin_app, serve_limits, shutdown_signal());
            tokio::select! {
                r = main_serve => r.map_err(Into::into),
                r = admin_serve => r.map_err(Into::into),
            }
        } else {
            main_serve.await.map_err(Into::into)
        };

    refresh_shutdown.cancel();
    // The consultation service owns cancellation-shielded accepted work and a
    // database serving fence. Close admission, drain that work, and explicitly
    // release the fence before waiting on unrelated refresh tasks. A stuck
    // refresh must not delay single-active Relay failover.
    let consultation_shutdown: Result<(), Box<dyn StdError + Send + Sync>> =
        if let Some(consultation) = runtime.consultation.as_ref() {
            consultation
                .shutdown()
                .await
                .map_err(|err| Box::new(err) as Box<dyn StdError + Send + Sync>)
        } else {
            Ok(())
        };
    if let Err(err) = consultation_shutdown.as_ref() {
        warn!(error = %err, "consultation shutdown failed");
    }

    while let Some(joined) = refresh_tasks.join_next().await {
        if let Err(err) = joined {
            warn!(error = %err, "refresh task failed during shutdown");
        }
    }

    // Best-effort final audit flush after every runtime writer has stopped,
    // regardless of which listener tripped the shutdown.
    if let Err(err) = runtime.audit_sink.flush().await {
        warn!(error = %err, "audit flush on shutdown failed");
    }

    match (result, consultation_shutdown) {
        (Err(serve_error), _) => Err(serve_error),
        (Ok(()), Err(shutdown_error)) => Err(shutdown_error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_openapi(
    config_path: PathBuf,
    env_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    load_env_file_arg(env_file.as_deref())?;
    let config = reported_config_load(config::load(&config_path))?;
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
    expected_config_digest: Option<ExpectedConfigDigest>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match format {
        OutputFormat::Json => {
            let report = build_doctor_report(
                &config_path,
                env_file.as_deref(),
                profile_override,
                expected_config_digest.as_ref(),
            );
            println!("{}", serde_json::to_string_pretty(&report.output)?);
            if report.exit_success {
                Ok(())
            } else {
                Err(ProcessStartupFailure::new(ProcessStartupCode::DOCTOR_FAILED).into())
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
            let config = reported_config_load(config::load(&config_path))?;
            let raw = fs::read_to_string(&config_path)?;
            let expanded = expand_config_env_vars(&raw)?;
            let resolved_config = redacted_resolved_config(&expanded)?;
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
            print!("{}", config::schema::document_json());
            Ok(())
        }
    }
}

fn build_doctor_report(
    config_path: &std::path::Path,
    env_file: Option<&std::path::Path>,
    profile_override: Option<DeploymentProfile>,
    expected_config_digest: Option<&ExpectedConfigDigest>,
) -> DoctorReport {
    let mut checks = Vec::new();
    let mut report_source = ConfigSource::LocalFile;
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
        return DoctorReport::new(checks, None, profile_override, report_source);
    }

    if let Some(expected_config_digest) = expected_config_digest {
        checks.push(expected_config_generation_check(
            config_path,
            expected_config_digest,
        ));
        if checks.iter().any(|check| check.status == "failed") {
            return DoctorReport::new(checks, None, profile_override, report_source);
        }
    }

    let loaded_config = match config::load_with_metadata(config_path) {
        Ok(mut loaded) => {
            report_source = loaded.provenance.source;
            checks.push(DoctorCheck::passed(
                "config",
                "relay.config.loaded",
                "config parsed and validated",
                None,
            ));
            match suppress_runtime_source_diagnostics(|| {
                EntityRegistry::from_config(&loaded.runtime)
            }) {
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
            match (
                loaded.runtime.consultation.is_some(),
                loaded.consultation_artifacts.take(),
            ) {
                (true, Some(artifacts)) => match suppress_runtime_source_diagnostics(|| {
                    ConsultationService::validate_configuration(&loaded.runtime, artifacts)
                }) {
                    Ok(()) => checks.push(DoctorCheck::passed(
                        "consultation_artifacts",
                        "relay.consultation_artifacts.verified",
                        "consultation artifact closure compiled with closed runtime capabilities",
                        None,
                    )),
                    Err(error) => checks.push(consultation_activation_doctor_check(error)),
                },
                (false, None) => checks.push(DoctorCheck::passed(
                    "consultation_artifacts",
                    "relay.consultation_artifacts.not_configured",
                    "consultation artifacts are not configured",
                    None,
                )),
                (true, None) => checks.push(consultation_activation_doctor_check(
                    ConsultationServiceActivationError::RegistryActivation,
                )),
                (false, Some(_)) => checks.push(consultation_activation_doctor_check(
                    ConsultationServiceActivationError::MissingConfiguration,
                )),
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
        report_source,
    )
}

fn expected_config_generation_check(
    config_path: &std::path::Path,
    expected_config_digest: &ExpectedConfigDigest,
) -> DoctorCheck {
    match fs::read(config_path) {
        Ok(bytes) if sha256_uri(&bytes) == expected_config_digest.as_str() => DoctorCheck::passed(
            "config_generation",
            "relay.config.generation_verified",
            "the mounted configuration is the expected generated revision",
            None,
        ),
        Ok(_) => DoctorCheck::failed(
            "config_generation",
            "relay.config.generation_mismatch",
            "the mounted configuration is not the expected generated revision",
            Some("wait for the container filesystem view to refresh, then retry"),
        ),
        Err(_) => DoctorCheck::failed(
            "config_generation",
            "relay.config.generation_unavailable",
            "the expected generated configuration is not readable",
            Some("check the generated configuration mount, then retry"),
        ),
    }
}

fn parse_doctor_config_without_validation(config_path: &std::path::Path) -> Option<Config> {
    let raw = fs::read_to_string(config_path).ok()?;
    let expanded = expand_config_env_vars(&raw).ok()?;
    serde_saphyr::from_str(&expanded).ok()
}

fn suppress_runtime_source_diagnostics<T>(action: impl FnOnce() -> T) -> T {
    let dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    tracing::dispatcher::with_default(&dispatch, action)
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
        source: ConfigSource,
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
                "kind": source.as_posture_str(),
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
        if let Some(config) = config {
            output["audit_shipping"] = audit_shipping_report(config);
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

fn consultation_activation_doctor_check(error: ConsultationServiceActivationError) -> DoctorCheck {
    let projection = error.safe_projection();
    DoctorCheck::failed(
        "consultation_artifacts",
        projection.code.as_str(),
        projection.meaning,
        Some(projection.remediation),
    )
}

#[derive(Debug)]
struct OperatorSafeConsultationActivationFailure(ConsultationServiceActivationFailure);

impl From<ConsultationServiceActivationError> for OperatorSafeConsultationActivationFailure {
    fn from(error: ConsultationServiceActivationError) -> Self {
        Self(error.safe_projection())
    }
}

impl std_fmt::Display for OperatorSafeConsultationActivationFailure {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        write!(
            formatter,
            "{}: {} Next action: {}",
            self.0.code, self.0.meaning, self.0.remediation
        )
    }
}

impl StdError for OperatorSafeConsultationActivationFailure {}

impl OperatorSafeConsultationActivationFailure {
    fn emit(&self) {
        error!(
            code = self.0.code.as_str(),
            meaning = self.0.meaning,
            remediation = self.0.remediation,
            "registry-relay consultation activation rejected startup"
        );
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
    if let Some(consultation) = &config.consultation {
        for name in consultation.required_environment_references() {
            envs.insert(name.to_owned(), ConfigValueClassification::Secret);
        }
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
    sections
}

fn relay_live_apply_classes() -> Vec<Value> {
    [
        ("auth.api_keys", LiveApplyClass::HotSwappable),
        ("auth.oidc", LiveApplyClass::HotSwappable),
        // The consultation state plane derives its durable chain authority
        // from audit.hash_secret_env at startup. Treat the whole audit block as
        // restart-only so a future live-apply implementation cannot split the
        // HTTP and consultation audit authorities.
        ("audit", LiveApplyClass::RestartRequired),
        ("catalog", LiveApplyClass::HotSwappable),
        ("consultation", LiveApplyClass::RestartRequired),
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

    if path == ["consultation", "state_plane", "root_certificate_path"] {
        return ConfigValueClassification::TopologySensitive;
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

async fn run_product_action(
    command: ProductActionCommand,
    trust_domain: ProductTrustDomainV1,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bundle_path = std::path::Path::new(PRODUCT_BUNDLE_PATH);
    let anchor_path = std::path::Path::new(PRODUCT_ANCHOR_PATH);
    let state_path = std::path::Path::new(PRODUCT_ANTIROLLBACK_STATE_PATH);

    let input = reported_config_load(match trust_domain {
        ProductTrustDomainV1::Governed => config::loader::load_verified_product_action_input(
            bundle_path,
            anchor_path,
            command.lane,
        ),
        ProductTrustDomainV1::Development => {
            config::loader::load_verified_development_action_input(
                bundle_path,
                anchor_path,
                command.lane,
            )
        }
    })?;
    verify_product_action_runtime_lane(command.lane, input.runtime())?;

    match command.action {
        ProductAction::PrepareStateStore => {
            let audit_sink = build_product_action_audit_sink(input.runtime())?;
            write_signed_product_action_intent_audit(
                &audit_sink,
                "prepare_state_store",
                &input.verified,
            )
            .await?;
            let state_plane = if command.lane == config::loader::RelayProductLane::Consultation {
                let result = prepare_state_store_from_signed_policy(input.runtime()).await?;
                serde_json::to_value(result.state_plane)?
            } else {
                Value::String("not_required".to_string())
            };
            print_json_report(json!({
                "schema": "registry.relay.product-action-result.v1",
                "action": PREPARE_STATE_STORE_ACTION,
                "status": "succeeded",
                "state_plane": state_plane,
            }))
        }
        ProductAction::InitializeState => {
            let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&input.verified)
                .map_err(|_| product_acceptance_failure())?;
            let store = FileAntiRollbackStore::new(state_path);
            let plan = store
                .plan_initialize(&candidate)
                .map_err(|_| product_acceptance_failure())?;
            let audit_sink = build_product_action_audit_sink(input.runtime())?;
            let signer_kids = input.verified.signer_kids.clone();
            let previous_config_hash = input.verified.manifest.previous_config_hash.clone();
            let initialize_consultation = (command.lane
                == config::loader::RelayProductLane::Consultation)
                .then_some(input.runtime());
            store
                .commit_acceptance(plan, move |intent| async move {
                    write_acceptance_intent_audit(
                        &audit_sink,
                        &intent,
                        &signer_kids,
                        previous_config_hash.as_deref(),
                    )
                    .await?;
                    if let Some(runtime) = initialize_consultation {
                        initialize_state_from_signed_policy(runtime).await?;
                    }
                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                })
                .await
                .map_err(|_| product_acceptance_failure())?;
            print_json_report(json!({
                "schema": "registry.relay.product-action-result.v1",
                "action": INITIALIZE_STATE_ACTION,
                "status": "succeeded",
            }))
        }
        ProductAction::PreviewState => {
            ensure_governed_state_action(trust_domain)?;
            let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&input.verified)
                .map_err(|_| product_acceptance_failure())?;
            let (preview, _, _) =
                preview_product_acceptance(&FileAntiRollbackStore::new(state_path), &candidate)?;
            print_json_report(json!({
                "schema": "registry.relay.product-action-result.v1",
                "action": PREVIEW_STATE_ACTION,
                "status": "previewed",
                "state": preview.as_str(),
            }))
        }
        ProductAction::AcceptState => {
            ensure_governed_state_action(trust_domain)?;
            let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&input.verified)
                .map_err(|_| product_acceptance_failure())?;
            let store = FileAntiRollbackStore::new(state_path);
            let (preview, previous_anchor, transition) =
                preview_product_acceptance(&store, &candidate)?;
            if preview != AcceptanceStatePreviewV1::Current {
                let plan = store
                    .plan_acceptance(&candidate, previous_anchor.as_ref(), transition.as_ref())
                    .map_err(|_| product_acceptance_failure())?;
                let audit_sink = build_product_action_audit_sink(input.runtime())?;
                let signer_kids = input.verified.signer_kids.clone();
                let previous_config_hash = input.verified.manifest.previous_config_hash.clone();
                store
                    .commit_acceptance(plan, move |intent| async move {
                        write_acceptance_intent_audit(
                            &audit_sink,
                            &intent,
                            &signer_kids,
                            previous_config_hash.as_deref(),
                        )
                        .await
                    })
                    .await
                    .map_err(|_| product_acceptance_failure())?;
            }
            print_json_report(json!({
                "schema": "registry.relay.product-action-result.v1",
                "action": ACCEPT_STATE_ACTION,
                "status": "succeeded",
                "state": preview.as_str(),
            }))
        }
        ProductAction::VerifyState => {
            ensure_governed_state_action(trust_domain)?;
            let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&input.verified)
                .map_err(|_| product_acceptance_failure())?;
            FileAntiRollbackStore::new(state_path)
                .verify_state(candidate.expectation())
                .map_err(|_| product_acceptance_failure())?;
            print_json_report(json!({
                "schema": "registry.relay.product-action-result.v1",
                "action": VERIFY_STATE_ACTION,
                "status": "verified",
            }))
        }
        ProductAction::Serve => {
            let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&input.verified)
                .map_err(|_| product_acceptance_failure())?;
            FileAntiRollbackStore::new(state_path)
                .verify_state(candidate.expectation())
                .map_err(|_| product_acceptance_failure())?;
            run_server(
                ServeConfigSource::SignedBundle {
                    bundle_dir: bundle_path.to_path_buf(),
                    anchor_path: anchor_path.to_path_buf(),
                    state_path: state_path.to_path_buf(),
                    expected_lane: Some(command.lane),
                },
                None,
                None,
                Some(input),
            )
            .await
        }
    }
}

fn ensure_governed_state_action(
    trust_domain: ProductTrustDomainV1,
) -> Result<(), ProcessStartupFailure> {
    (trust_domain == ProductTrustDomainV1::Governed)
        .then_some(())
        .ok_or_else(|| ProcessStartupFailure::new(ProcessStartupCode::BUNDLE_BINDING_REJECTED))
}

type ProductRotationInputs = (
    AcceptanceStatePreviewV1,
    Option<registry_platform_config::ConfigTrustAnchor>,
    Option<registry_platform_config::AnchorTransitionV1>,
);

fn preview_product_acceptance(
    store: &FileAntiRollbackStore,
    candidate: &VerifiedAcceptanceStateV1,
) -> Result<ProductRotationInputs, ProcessStartupFailure> {
    match store.preview_acceptance(candidate, None, None) {
        Ok(preview) => Ok((preview, None, None)),
        Err(AntiRollbackStoreError::AnchorTransitionRequired) => {
            let (previous_anchor, transition) = load_optional_product_rotation_inputs()?;
            let preview = store
                .preview_acceptance(candidate, previous_anchor.as_ref(), transition.as_ref())
                .map_err(|_| product_acceptance_failure())?;
            Ok((preview, previous_anchor, transition))
        }
        Err(_) => Err(product_acceptance_failure()),
    }
}

fn load_optional_product_rotation_inputs() -> Result<
    (
        Option<registry_platform_config::ConfigTrustAnchor>,
        Option<registry_platform_config::AnchorTransitionV1>,
    ),
    ProcessStartupFailure,
> {
    let previous = load_optional_closed_product_file(
        std::path::Path::new(PRODUCT_PREVIOUS_ANCHOR_PATH),
        load_trust_anchor,
    )?;
    let transition = load_optional_closed_product_file(
        std::path::Path::new(PRODUCT_ANCHOR_TRANSITION_PATH),
        load_anchor_transition,
    )?;
    if previous.is_some() != transition.is_some() {
        return Err(product_acceptance_failure());
    }
    Ok((previous, transition))
}

fn load_optional_closed_product_file<T>(
    path: &std::path::Path,
    loader: impl FnOnce(&std::path::Path) -> Result<T, registry_platform_config::ConfigBundleError>,
) -> Result<Option<T>, ProcessStartupFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => loader(path)
            .map(Some)
            .map_err(|_| product_acceptance_failure()),
        Ok(_) => Err(product_acceptance_failure()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(product_acceptance_failure()),
    }
}

fn product_acceptance_failure() -> ProcessStartupFailure {
    ProcessStartupFailure::new(ProcessStartupCode::BUNDLE_ROLLBACK_REJECTED)
}

fn verify_product_action_runtime_lane(
    lane: config::loader::RelayProductLane,
    runtime: &Config,
) -> Result<(), ProcessStartupFailure> {
    config::loader::verify_relay_runtime_lane_binding(lane, runtime)
        .map_err(|_| ProcessStartupFailure::new(ProcessStartupCode::BUNDLE_BINDING_REJECTED))
}

fn build_product_action_audit_sink(
    config: &Config,
) -> Result<Arc<AuditPipeline>, Box<dyn std::error::Error + Send + Sync>> {
    let profile = build_audit_chain_profile(config)
        .map_err(|_| ProcessStartupFailure::new(ProcessStartupCode::CONFIG_VALIDATION_REJECTED))?;
    build_audit_sink(config, profile).map_err(Into::into)
}

async fn write_signed_product_action_intent_audit(
    audit_sink: &AuditPipeline,
    action: &'static str,
    verified: &registry_platform_config::VerifiedConfigBundle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let anchor_digest = registry_platform_config::trust_anchor_digest(&verified.trust_anchor)
        .map_err(|_| product_acceptance_failure())?;
    let audit = product_action_config_audit(
        action,
        verified.manifest.acceptance_identity.clone(),
        verified.manifest.bundle_id.clone(),
        verified.manifest_hash.clone(),
        verified.manifest.sequence,
        verified.signer_kids.clone(),
        verified.manifest.previous_config_hash.clone(),
        verified.manifest.config_hash.clone(),
        anchor_digest,
        verified.trust_anchor.version,
    );
    audit_sink
        .write_operational_event(
            OperationalAuditEvent::success("product_action.mutation_intent").with_config(audit),
        )
        .await?;
    Ok(())
}

async fn write_acceptance_intent_audit(
    audit_sink: &AuditPipeline,
    intent: &AcceptanceAuditIntentV1,
    signer_kids: &[String],
    previous_config_hash: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let action = match intent.mutation {
        AcceptanceMutationKindV1::Initialize => "initialize_state",
        AcceptanceMutationKindV1::Advance => "accept_update",
        AcceptanceMutationKindV1::RotateAnchor => "rotate_anchor",
    };
    let audit = product_action_config_audit(
        action,
        intent.key.acceptance_identity.clone(),
        intent.bundle_id.clone(),
        intent.bundle_manifest_hash.clone(),
        intent.sequence,
        signer_kids.to_vec(),
        previous_config_hash.map(ToString::to_string),
        intent.config_hash.clone(),
        intent.anchor_digest.clone(),
        intent.anchor_version,
    );
    audit_sink
        .write_operational_event(
            OperationalAuditEvent::success("config.acceptance_mutation_intent").with_config(audit),
        )
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn product_action_config_audit(
    action: &'static str,
    acceptance_identity: registry_platform_config::ProductAcceptanceIdentityV1,
    bundle_id: String,
    bundle_manifest_hash: String,
    sequence: u64,
    signer_kids: Vec<String>,
    previous_config_hash: Option<String>,
    config_hash: String,
    anchor_digest: String,
    anchor_version: u64,
) -> ConfigAuditExt {
    ConfigAuditExt {
        action,
        source: ConfigSource::SignedBundleFile.as_posture_str(),
        acceptance_identity: Some(acceptance_identity),
        bundle_id: Some(bundle_id),
        bundle_manifest_hash: Some(bundle_manifest_hash),
        sequence: Some(sequence),
        signer_kids,
        previous_config_hash,
        previous_hash_matched: None,
        config_hash: Some(config_hash),
        anchor_digest: Some(anchor_digest),
        anchor_version: Some(anchor_version),
        product_validation_result: "accepted",
        apply_result: "pending",
        posture_result: "accepted",
        applied: false,
        restart_required: false,
        change_classes: Vec::new(),
        break_glass: false,
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
    }
}

async fn run_config_verify_bundle(
    command: ConfigVerifyBundleCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let verified = match verify_config_bundle(&command.bundle_dir, &command.anchor_path) {
        Ok(verified) => verified,
        Err(error) => {
            let code = bundle_verify_rejection_code(&error);
            print_json_report(config_verify_bundle_report(
                ApplyReportResult::from(code),
                None,
                None,
                None,
                None,
                None,
                Some(code),
            ))?;
            return Err(
                ProcessStartupFailure::new(ProcessStartupCode::from_bundle_verification(code))
                    .into(),
            );
        }
    };
    if let Err(code) = config::loader::verify_relay_direct_bundle_binding(&verified) {
        print_json_report(config_verify_bundle_report(
            ApplyReportResult::from(code),
            None,
            None,
            None,
            None,
            None,
            Some(code),
        ))?;
        return Err(
            ProcessStartupFailure::new(ProcessStartupCode::from_bundle_verification(code)).into(),
        );
    }
    let candidate = match VerifiedAcceptanceStateV1::from_verified_bundle(&verified) {
        Ok(candidate) => candidate,
        Err(error) => {
            let code = registry_platform_ops::ConfigBootError::Store(error).bundle_rejection_code();
            print_json_report(config_verify_bundle_report(
                ApplyReportResult::from(code),
                None,
                None,
                None,
                None,
                None,
                Some(code),
            ))?;
            return Err(
                ProcessStartupFailure::new(ProcessStartupCode::from_bundle_verification(code))
                    .into(),
            );
        }
    };
    if let Err(error) =
        FileAntiRollbackStore::new(&command.state_path).verify_state(candidate.expectation())
    {
        let error = registry_platform_ops::ConfigBootError::Store(error);
        let code = error.bundle_rejection_code();
        print_json_report(config_verify_bundle_report(
            ApplyReportResult::from(code),
            None,
            None,
            None,
            None,
            None,
            Some(code),
        ))?;
        return Err(
            ProcessStartupFailure::new(ProcessStartupCode::from_bundle_verification(code)).into(),
        );
    }
    if config::validate_verified_bundle_runtime(&verified).is_err() {
        let code = BundleVerificationCode::REJECTED_VALIDATION;
        print_json_report(config_verify_bundle_report(
            ApplyReportResult::from(code),
            None,
            None,
            None,
            None,
            None,
            Some(code),
        ))?;
        return Err(
            ProcessStartupFailure::new(ProcessStartupCode::BUNDLE_VALIDATION_REJECTED).into(),
        );
    }

    print_json_report(config_verify_bundle_report(
        ApplyReportResult::Verified,
        Some(verified.manifest.acceptance_identity.stream),
        Some(verified.manifest.bundle_id),
        Some(verified.manifest.sequence),
        verified.manifest.previous_config_hash,
        Some(verified.manifest.config_hash),
        None,
    ))?;
    Ok(())
}

fn print_json_report(value: Value) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn config_verify_bundle_report(
    result: ApplyReportResult,
    stream_id: Option<String>,
    bundle_id: Option<String>,
    bundle_sequence: Option<u64>,
    previous_config_hash: Option<String>,
    config_hash: Option<String>,
    error: Option<BundleVerificationCode>,
) -> Value {
    // Rejection inputs are untrusted. Even when authenticity succeeded before
    // a later anti-rollback or product-validation failure, do not publish
    // bundle, stream, sequence, or hash identity through this report.
    let (stream_id, bundle_id, bundle_sequence, previous_config_hash, config_hash) =
        if error.is_some() {
            (None, None, None, None, None)
        } else {
            (
                stream_id,
                bundle_id,
                bundle_sequence,
                previous_config_hash,
                config_hash,
            )
        };
    let errors = error
        .map(|code| {
            let definition = code.definition();
            vec![json!({
                "code": code.as_str(),
                "message": definition.safe_report_message,
            })]
        })
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
        "result": result.as_str(),
        "restart_required": false,
        "change_classes": [],
        "affected_components": [],
        "warnings": [],
        "errors": errors,
    })
}

/// Offline audit-chain recovery (#196). Quarantines a retained chain that no
/// longer verifies under the configured keyed hasher and starts a fresh,
/// break segment. Refuses to run while a relay holds the single-writer lock.
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
    compile_relay_runtime_with_options(
        ServeConfigSource::LocalFile { config_path },
        bind_override,
        config::LoadOptions::default(),
    )
    .await
}

async fn compile_relay_runtime_with_options(
    config_source: ServeConfigSource,
    bind_override: Option<SocketAddr>,
    load_options: config::LoadOptions,
) -> Result<RelayRuntimeSnapshot, Box<dyn std::error::Error + Send + Sync>> {
    info!("loading registry-relay config");

    let loaded = reported_config_load(match &config_source {
        ServeConfigSource::LocalFile { config_path } => {
            config::load_with_metadata_options(config_path, load_options)
        }
        ServeConfigSource::SignedBundle {
            bundle_dir,
            anchor_path,
            state_path,
            expected_lane,
        } => match expected_lane {
            Some(expected_lane) => {
                config::loader::load_verified_product_bundle_with_metadata_for_lane(
                    bundle_dir,
                    anchor_path,
                    *expected_lane,
                )
            }
            None => config::loader::load_verified_bundle_with_metadata_options(
                bundle_dir,
                anchor_path,
                state_path,
                load_options,
            ),
        },
    })?;
    compile_loaded_relay_runtime(loaded, bind_override).await
}

async fn compile_loaded_relay_runtime(
    loaded: config::loader::LoadedConfig,
    bind_override: Option<SocketAddr>,
) -> Result<RelayRuntimeSnapshot, Box<dyn std::error::Error + Send + Sync>> {
    let config_provenance = loaded.provenance.clone();
    let pending_bundle_acceptance = loaded.pending_bundle_acceptance.clone();
    let compiled_metadata = loaded.metadata.map(Arc::new);
    let metadata_source_digest = loaded.metadata_source_digest;
    let consultation_artifacts = loaded.consultation_artifacts;
    let config = Arc::new(loaded.runtime);

    let auth = build_auth(&config)
        .with_subscriber(tracing::subscriber::NoSubscriber::default())
        .await
        .map_err(|_| ProcessStartupFailure::new(ProcessStartupCode::CONFIG_VALIDATION_REJECTED))?;
    let audit_chain_profile = build_audit_chain_profile(&config)
        .map_err(|_| ProcessStartupFailure::new(ProcessStartupCode::CONFIG_VALIDATION_REJECTED))?;
    let audit_sink = build_audit_sink(&config, audit_chain_profile.clone())?;
    // Eagerly verify the retained audit chain so a chain bricked by an earlier
    // fork surfaces as an actionable /ready signal instead of a per-request 503
    // behind a green healthcheck (#196). Startup is not aborted: readiness
    // reports not-ready until the operator recovers with `registry-relay audit
    // quarantine`.
    if audit_sink.verify_chain_eager().await.is_err() {
        error!(
            code = registry_relay::audit::AUDIT_CHAIN_INCONSISTENT_CODE,
            "audit chain failed startup verification; /ready will report not-ready until it is recovered"
        );
    }
    // Boot-time validation already logged waived gates; now that the audit
    // pipeline exists, record them durably with the accepted source.
    registry_relay::server::audit_waived_deployment_gates(
        &config,
        &audit_sink,
        config_provenance.source,
    )
    .await?;
    let bind: SocketAddr = bind_override.unwrap_or(config.server.bind);
    let admin_bind: Option<SocketAddr> = config.server.admin_bind;
    let audit_kind = audit_sink_kind(&config);
    let df_ctx = Arc::new(SessionContext::new());
    let formats = Arc::new(FormatRegistry::with_v1_defaults());
    let cache_root = Arc::from(config.server.cache_dir.as_path());
    let ingest = Arc::new(
        suppress_runtime_source_diagnostics(|| {
            IngestRegistry::from_config(&config, formats, cache_root, Arc::clone(&df_ctx))
        })
        .map_err(|_| {
            ProcessStartupFailure::new(ProcessStartupCode::RUNTIME_INITIALIZATION_FAILED)
        })?,
    );
    let entity_registry = Arc::new(
        suppress_runtime_source_diagnostics(|| EntityRegistry::from_config(&config)).map_err(
            |_| ProcessStartupFailure::new(ProcessStartupCode::CONFIG_VALIDATION_REJECTED),
        )?,
    );
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

    #[cfg(feature = "spdci-api-standards")]
    let spdci_response_mapper = build_spdci_response_mapper(&config)?.map(Arc::new);
    let metrics = RequestMetrics::shared();
    let consultation = match (config.consultation.is_some(), consultation_artifacts) {
        (false, None) => None,
        (true, Some(artifacts)) => Some(
            ConsultationService::activate(
                config.as_ref(),
                artifacts,
                audit_chain_profile.hasher(),
                Arc::clone(&df_ctx),
            )
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(OperatorSafeConsultationActivationFailure::from)?,
        ),
        _ => {
            return Err(ProcessStartupFailure::new(
                ProcessStartupCode::CONSULTATION_ARTIFACTS_REJECTED,
            )
            .into());
        }
    };
    if let Some(service) = consultation.as_ref() {
        service.bind_ingest_registry(ingest.as_ref())?;
    }

    Ok(RelayRuntimeSnapshot::new(
        config,
        config_provenance,
        compiled_metadata,
        metadata_source_digest,
        None,
        pending_bundle_acceptance,
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
        consultation,
        #[cfg(feature = "spdci-api-standards")]
        spdci_response_mapper,
        metrics,
    ))
}

async fn write_boot_config_audits(
    audit_sink: &AuditPipeline,
    acceptance: &config::PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if acceptance.emits_break_glass_used_audit() {
        write_break_glass_used_audit(audit_sink, acceptance).await?;
    }
    if acceptance.source == ConfigSource::SignedBundleFile {
        write_bundle_acceptance_audit(audit_sink, acceptance).await?;
    }
    Ok(())
}

async fn write_bundle_acceptance_audit(
    audit_sink: &AuditPipeline,
    acceptance: &config::PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Accepted bundle identity and signer evidence is intentionally retained
    // here. The audit sink, including the stdout sink, is a governed protected
    // evidence boundary. This must not be weakened to match the untrusted
    // rejection-report boundary.
    let audit = ConfigAuditExt {
        action: "boot",
        source: acceptance.source.as_posture_str(),
        acceptance_identity: None,
        bundle_id: acceptance.bundle_id.clone(),
        bundle_manifest_hash: acceptance.bundle_manifest_hash.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        anchor_digest: Some(acceptance.accepted_anchor.digest.clone()),
        anchor_version: Some(acceptance.accepted_anchor.version),
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
        acceptance_identity: None,
        bundle_id: acceptance.bundle_id.clone(),
        bundle_manifest_hash: acceptance.bundle_manifest_hash.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        anchor_digest: Some(acceptance.accepted_anchor.digest.clone()),
        anchor_version: Some(acceptance.accepted_anchor.version),
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
    persist_config_bundle_acceptance(acceptance)?;
    Ok(())
}

fn build_relay_app_from_runtime(
    handle: Arc<RelayRuntimeHandle>,
) -> Result<axum::Router, Box<dyn std::error::Error + Send + Sync>> {
    let runtime = handle.load_full();
    let auth: AuthProviderRef = Arc::new(RuntimeAuthProvider::new(Arc::clone(&handle)));
    let app = registry_relay::server::build_app_with_entity_query_metadata_and_metrics(
        Arc::clone(&runtime.config),
        auth,
        Arc::clone(&runtime.audit_sink),
        runtime.readiness_rx.clone(),
        Arc::clone(&runtime.entity_registry),
        Arc::clone(&runtime.query),
        Arc::clone(&runtime.aggregate_query),
        runtime.compiled_metadata.clone(),
        Arc::clone(&runtime.metrics),
    )?;
    #[cfg(feature = "spdci-api-standards")]
    let app = if let Some(spdci_response_mapper) = &runtime.spdci_response_mapper {
        app.layer(Extension(Arc::clone(spdci_response_mapper)))
    } else {
        app
    };
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
    } else if rest
        .first()
        .is_some_and(|arg| arg == SYNTHETIC_SOURCE_COMMAND)
    {
        parse_synthetic_source_command(&rest[1..])
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
    } else if rest
        .first()
        .is_some_and(|arg| arg == PRODUCT_ACTION_COMMAND)
    {
        parse_product_action_command(&rest[1..], false)
    } else if rest
        .first()
        .is_some_and(|arg| arg == DEVELOPMENT_ACTION_COMMAND)
    {
        parse_product_action_command(&rest[1..], true)
    } else if rest.first().is_some_and(|arg| arg == CONSULTATION_COMMAND) {
        Err(CliError(
            "consultation bootstrap-state is replaced by signed product-action".to_string(),
        ))
    } else if rest.first().is_some_and(|arg| arg == AUDIT_COMMAND) {
        parse_audit_command(&rest[1..])
    } else {
        parse_serve_command(&rest)
    }
}

fn parse_synthetic_source_command(args: &[String]) -> Result<CliCommand, CliError> {
    let (action, args) = match args.first().map(String::as_str) {
        Some(SYNTHETIC_SOURCE_PROBE_ACTION) => ("probe", &args[1..]),
        _ => ("serve", args),
    };
    if args.len() != 2 || args[0] != PLAN_FLAG {
        let action = if action == "probe" { " probe" } else { "" };
        return Err(CliError(format!(
            "{SYNTHETIC_SOURCE_COMMAND}{action} requires exactly {PLAN_FLAG} <path>"
        )));
    }
    let plan_path = required_path_value(PLAN_FLAG, &args[1])?;
    Ok(CliCommand::SyntheticSource(match action {
        "probe" => SyntheticSourceCommand::Probe { plan_path },
        "serve" => SyntheticSourceCommand::Serve { plan_path },
        _ => unreachable!("synthetic-source action parser is closed"),
    }))
}

fn parse_product_action_command(
    args: &[String],
    development: bool,
) -> Result<CliCommand, CliError> {
    let namespace = if development {
        DEVELOPMENT_ACTION_COMMAND
    } else {
        PRODUCT_ACTION_COMMAND
    };
    if args.len() != 2 {
        return Err(CliError(format!(
            "{namespace} requires one canonical Relay lane and one closed action"
        )));
    }
    let lane = match args[0].as_str() {
        "relay-public" => config::loader::RelayProductLane::Public,
        "relay-consultation" => config::loader::RelayProductLane::Consultation,
        _ => {
            return Err(CliError(format!(
                "{namespace} lane must be relay-public or relay-consultation"
            )));
        }
    };
    let action = match (development, args[1].as_str()) {
        (_, PREPARE_STATE_STORE_ACTION) => ProductAction::PrepareStateStore,
        (_, INITIALIZE_STATE_ACTION) => ProductAction::InitializeState,
        (false, PREVIEW_STATE_ACTION) => ProductAction::PreviewState,
        (false, ACCEPT_STATE_ACTION) => ProductAction::AcceptState,
        (false, VERIFY_STATE_ACTION) => ProductAction::VerifyState,
        (_, SERVE_ACTION) => ProductAction::Serve,
        (true, _) => {
            return Err(CliError(format!(
                "{namespace} action must be prepare_state_store, initialize_state, or serve"
            )));
        }
        (false, _) => {
            return Err(CliError(format!(
                "{namespace} action must be prepare_state_store, initialize_state, preview_state, accept_state, verify_state, or serve"
            )));
        }
    };
    let command = ProductActionCommand { lane, action };
    Ok(if development {
        CliCommand::DevelopmentAction(command)
    } else {
        CliCommand::ProductAction(command)
    })
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
    let mut expected_config_digest: Option<ExpectedConfigDigest> = None;
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
        } else if let Some(value) = flag_value(arg, EXPECTED_CONFIG_DIGEST_FLAG) {
            expected_config_digest = Some(ExpectedConfigDigest::parse(&required_string_value(
                EXPECTED_CONFIG_DIGEST_FLAG,
                value,
            )?)?);
        } else if arg == EXPECTED_CONFIG_DIGEST_FLAG {
            index += 1;
            expected_config_digest = Some(ExpectedConfigDigest::parse(&required_string_arg(
                args,
                index,
                EXPECTED_CONFIG_DIGEST_FLAG,
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
        expected_config_digest,
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
    let mut bundle_dir: Option<PathBuf> = None;
    let mut anchor_path: Option<PathBuf> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut env_file: Option<PathBuf> = None;
    let mut bind_override: Option<SocketAddr> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = flag_value(arg, CONFIG_FLAG) {
            config_path = Some(required_path_value(CONFIG_FLAG, value)?);
        } else if arg == CONFIG_FLAG {
            index += 1;
            config_path = Some(required_path_arg(args, index, CONFIG_FLAG)?);
        } else if let Some(value) = flag_value(arg, BUNDLE_DIR_FLAG) {
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
    let config_source = match (config_path, bundle_dir, anchor_path, state_path) {
        (Some(_), bundle_dir, anchor_path, state_path)
            if bundle_dir.is_some() || anchor_path.is_some() || state_path.is_some() =>
        {
            return Err(CliError(
                "local config cannot be combined with signed-bundle serve flags".to_string(),
            ));
        }
        (Some(config_path), None, None, None) => ServeConfigSource::LocalFile { config_path },
        (None, Some(bundle_dir), Some(anchor_path), Some(state_path)) => {
            if config_path_env_is_set() {
                return Err(CliError(
                    "local config cannot be combined with signed-bundle serve flags".to_string(),
                ));
            }
            ServeConfigSource::SignedBundle {
                bundle_dir,
                anchor_path,
                state_path,
                expected_lane: None,
            }
        }
        (None, None, None, None) => ServeConfigSource::LocalFile {
            config_path: default_config_path_from_env(),
        },
        (None, _, _, _) => {
            return Err(CliError(format!(
                "signed-bundle serve requires {BUNDLE_DIR_FLAG}, {ANCHOR_PATH_FLAG}, and {STATE_PATH_FLAG}"
            )));
        }
        (Some(_), _, _, _) => unreachable!("mixed config source handled above"),
    };
    Ok(CliCommand::Serve {
        config_source,
        env_file,
        bind_override,
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
    let Some(value) = args.get(index).filter(|value| !value.starts_with("--")) else {
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

fn config_path_env_is_set() -> bool {
    env::var_os("REGISTRY_RELAY_CONFIG").is_some_and(|value| !value.is_empty())
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

/// Load the deployment audit-chain profile exactly once for every runtime
/// capability that must share the same domain-separated chain key.
fn build_audit_chain_profile(config: &Config) -> Result<AuditChainProfile, Error> {
    let hash_secret_env = config
        .audit
        .hash_secret_env
        .as_deref()
        .ok_or(ConfigError::ValidationError)?;
    AuditChainProfile::registry_relay_from_env(hash_secret_env)
        .map_err(|_| Error::from(ConfigError::ValidationError))
}

/// Instantiate the configured audit sink with the already-loaded chain
/// profile shared by the consultation state plane.
fn build_audit_sink(
    config: &Config,
    profile: AuditChainProfile,
) -> Result<Arc<AuditPipeline>, ProcessStartupFailure> {
    let sink: Arc<dyn registry_platform_audit::AuditSink> = match &config.audit.sink {
        AuditSinkConfig::Stdout {} => Arc::new(StdoutSink::new()),
        AuditSinkConfig::File { path, rotate } => {
            match FileSink::new(path, rotate.max_size_mb, rotate.max_files) {
                Ok(sink) => Arc::new(sink),
                Err(_) => {
                    return Err(ProcessStartupFailure::new(
                        ProcessStartupCode::RUNTIME_INITIALIZATION_FAILED,
                    ));
                }
            }
        }
        AuditSinkConfig::Syslog {} => Arc::new(SyslogSink::new()),
        _ => {
            return Err(ProcessStartupFailure::new(
                ProcessStartupCode::CONFIG_VALIDATION_REJECTED,
            ));
        }
    };
    if !config.audit.chain {
        info!(
            "audit.chain is accepted for config compatibility; platform audit envelopes are always chained"
        );
    }
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

/// Report the audit shipping posture for the doctor diagnostic report. This
/// mirrors the `posture.audit` shipping fields: the declared state
/// (`sink_type`, `shipping_target_configured`, `shipping_target`) derived from
/// config via the shared classifier, plus the observed state
/// (`shipping_health`, `shipping_observed_at`) read from the local ack cursor.
fn audit_shipping_report(config: &Config) -> Value {
    let (sink_kind, sink_type) = match &config.audit.sink {
        AuditSinkConfig::Stdout { .. } => (AuditSinkKind::Stdout, "stdout"),
        AuditSinkConfig::Syslog { .. } => (AuditSinkKind::Syslog, "syslog"),
        AuditSinkConfig::File { .. } => (AuditSinkKind::LocalFile, "file"),
        _ => (AuditSinkKind::Unknown, "unknown"),
    };
    let (shipping_target_configured, shipping_target) =
        audit_shipping_target(sink_kind, config.deployment.evidence.audit_offhost_shipping);
    // Doctor is offline and has no live AuditPipeline, so a fresh cursor stays
    // unverified rather than being promoted to ok without keyed tail binding.
    let observation = registry_relay::deployment::audit_ack_observation(config);
    let (shipping_health, shipping_observed_at) =
        registry_relay::deployment::shipping_health_fields(
            &observation,
            shipping_target_configured,
        );
    json!({
        "sink_type": sink_type,
        "shipping_target_configured": shipping_target_configured,
        "shipping_target": shipping_target,
        "shipping_health": shipping_health,
        "shipping_observed_at": shipping_observed_at,
    })
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
        build_audit_chain_profile, build_audit_sink, build_doctor_report, compile_relay_runtime,
        consultation_activation_doctor_check, doctor_check_diagnostic, load_env_file_arg,
        parse_cli_command_from, parse_env_file_value, redacted_resolved_config,
        relay_config_value_classification, relay_live_apply_classes, render_generated_api_key,
        required_env_report, run_audit_quarantine, run_healthcheck, url_contains_userinfo,
        CliCommand, ConfigValueClassification, ConsultationServiceActivationError,
        ExpectedConfigDigest, GenerateApiKeyCommand, OperationalLogFormat,
        OperatorSafeConsultationActivationFailure, OutputFormat, ProcessStartupCode,
        ProcessStartupFailure, ProductAction, ProductActionCommand, ReportedConfigLoadFailure,
        ServeConfigSource, SyntheticSourceCommand, ACCEPT_STATE_ACTION,
        DEFAULT_HEALTHCHECK_TIMEOUT_MS, DEFAULT_HEALTHCHECK_URL, DEVELOPMENT_ACTION_COMMAND,
        INITIALIZE_STATE_ACTION, PREPARE_STATE_STORE_ACTION, PREVIEW_STATE_ACTION,
        PRODUCT_ACTION_COMMAND, SERVE_ACTION, VERIFY_STATE_ACTION,
    };
    use axum::routing::get;
    use axum::Router;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use registry_platform_audit::{
        verify_jsonl_lines_with_hasher, AuditChainHasher, AuditEnvelope, AuditError,
    };
    use registry_platform_config::{
        sha256_uri, verify_config_bundle, ConfigBundleFile, ConfigBundleManifest,
        ConfigBundleSignature, ConfigBundleSignatureEnvelope, ConfigTrustAnchor,
        ConfigTrustAnchorSigner, ProductAcceptanceIdentityV1, ProductAcceptanceLaneV1,
        ProductAcceptanceProductV1, ProductTrustDomainV1,
    };
    use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};
    use registry_platform_ops::{
        bundle_verify_rejection_code, AcceptedAnchorPinV1, AntiRollbackKey, AntiRollbackStoreError,
        BundleStateAction, BundleVerificationCode, ConfigOverrideMode, ConfigOverridePin,
        ConfigSource, DeploymentProfile, FileAntiRollbackStore, PendingBundleAcceptance,
    };
    use registry_relay::audit::{AuditPipeline, AuditRecord, EndpointKind, InMemorySink};
    use registry_relay::config::Config;
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex as StdMutex, OnceLock};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    const CONFIG_BUNDLE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

    #[test]
    fn consultation_activation_boundary_doctor_preserves_exact_distinct_codes() {
        let errors = [
            ConsultationServiceActivationError::MissingConfiguration,
            ConsultationServiceActivationError::UnsupportedPlan,
        ];
        let checks = errors.map(consultation_activation_doctor_check);

        assert_ne!(checks[0].code, checks[1].code);
        assert_ne!(checks[0].message, checks[1].message);
        for (error, check) in errors.into_iter().zip(checks) {
            let projection = error.safe_projection();
            assert_eq!(check.code, projection.code.as_str());
            assert_eq!(check.message, projection.meaning);
            assert_eq!(check.action, Some(projection.remediation));
            assert_ne!(check.code, "relay.consultation_artifacts.failed");

            let diagnostic = doctor_check_diagnostic(&check);
            assert_eq!(diagnostic["code"], projection.code.as_str());
            assert_eq!(
                diagnostic["message"],
                format!(
                    "{} Next action: {}",
                    projection.meaning, projection.remediation
                )
            );
        }
    }

    #[test]
    fn consultation_activation_boundary_startup_uses_only_static_safe_projection() {
        let errors = [
            ConsultationServiceActivationError::MissingConfiguration,
            ConsultationServiceActivationError::InvalidWorkloadBinding,
            ConsultationServiceActivationError::RegistryActivation,
            ConsultationServiceActivationError::UnsupportedPlan,
            ConsultationServiceActivationError::InvalidQuotaLimits,
            ConsultationServiceActivationError::InvalidMetadata,
            ConsultationServiceActivationError::SourceCredentials,
            ConsultationServiceActivationError::PseudonymMaterial,
            ConsultationServiceActivationError::StatePlane,
        ];
        let sentinels = [
            "/tmp/COUNTRY/private/source.yaml",
            "sha256:COUNTRY_HASH",
            "COUNTRY_PARSER_ERROR",
            "redaction-user@example.test",
            "COUNTRY_SECRET_VALUE",
            "COUNTRY_VALUE",
        ];

        for error in errors {
            let old_display = error.to_string();
            let projection = error.safe_projection();
            let rendered = OperatorSafeConsultationActivationFailure::from(error).to_string();
            assert_eq!(
                rendered,
                format!(
                    "{}: {} Next action: {}",
                    projection.code, projection.meaning, projection.remediation
                )
            );
            assert_ne!(
                rendered, old_display,
                "startup must not propagate the legacy activation Display"
            );
            for sentinel in sentinels {
                assert!(
                    !rendered.contains(sentinel),
                    "operator-safe startup failure leaked sentinel {sentinel:?}"
                );
            }
        }
    }

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
            config: None,
        }
    }

    #[derive(Debug)]
    struct FailingAuditSink;

    #[async_trait::async_trait]
    impl registry_platform_audit::AuditSink for FailingAuditSink {
        async fn write(&self, _envelope: &AuditEnvelope) -> Result<(), AuditError> {
            Err(AuditError::Io(std::io::Error::other(
                "boot audit write failed",
            )))
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }
    }

    fn test_hash(label: char) -> String {
        format!("sha256:{}", label.to_string().repeat(64))
    }

    struct SignedRelayBundleFixture {
        bundle_dir: PathBuf,
        anchor_path: PathBuf,
        state_path: PathBuf,
    }

    fn write_signed_relay_bundle(
        tmp: &tempfile::TempDir,
        hash_secret_env: &str,
    ) -> SignedRelayBundleFixture {
        let bundle_dir = tmp.path().join("bundle");
        let config_dir = bundle_dir.join("config");
        std::fs::create_dir_all(&config_dir).expect("bundle config dir");
        let config = runtime_config_yaml(hash_secret_env);
        let config_path = config_dir.join("relay.yaml");
        std::fs::write(&config_path, config.as_bytes()).expect("config writes");
        let config_hash = sha256_uri(config.as_bytes());
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
        let public = private.public();
        let kid = public.jkt().expect("thumbprint");
        let acceptance_identity = ProductAcceptanceIdentityV1 {
            trust_domain: ProductTrustDomainV1::Governed,
            project: "relay-bind-project".to_string(),
            environment: "lab".to_string(),
            lane: ProductAcceptanceLaneV1::RelayPublic,
            product: ProductAcceptanceProductV1::RegistryRelay,
            stream: "relay-bind-test".to_string(),
            instance: "relay-bind-test".to_string(),
        };
        let manifest = ConfigBundleManifest {
            schema: "registry.platform.config_bundle.v1".to_string(),
            acceptance_identity: acceptance_identity.clone(),
            bundle_id: "relay-bind-bundle".to_string(),
            sequence: 1,
            previous_config_hash: None,
            config_hash: config_hash.clone(),
            files: vec![ConfigBundleFile {
                path: "config/relay.yaml".to_string(),
                sha256: config_hash,
            }],
            created_at: "2026-07-07T10:00:00Z".to_string(),
        };
        write_bundle_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);
        let anchor = ConfigTrustAnchor {
            schema: "registry.platform.config_trust_anchor.v1".to_string(),
            acceptance_identity,
            version: 1,
            threshold: 1,
            enabled_signers: vec![ConfigTrustAnchorSigner { kid, jwk: public }],
        };
        let anchor_path = tmp.path().join("trust_anchor.json");
        std::fs::write(
            &anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
        )
        .expect("anchor writes");
        SignedRelayBundleFixture {
            bundle_dir,
            anchor_path,
            state_path: tmp.path().join("antirollback.json"),
        }
    }

    fn write_bundle_manifest_and_signature(
        bundle_dir: &Path,
        manifest: &ConfigBundleManifest,
        private: &PrivateJwk,
        kid: &str,
    ) {
        let manifest_value = serde_json::to_value(manifest).expect("manifest value");
        let canonical = canonicalize_json(&manifest_value).expect("canonical manifest");
        let signature = sign(&canonical, private).expect("manifest signs");
        let envelope = ConfigBundleSignatureEnvelope {
            schema: "registry.platform.config_bundle_signatures.v1".to_string(),
            signatures: vec![ConfigBundleSignature {
                kid: kid.to_string(),
                alg: "EdDSA".to_string(),
                sig: URL_SAFE_NO_PAD.encode(signature),
            }],
        };
        std::fs::write(
            bundle_dir.join("manifest.json"),
            serde_json::to_vec_pretty(manifest).expect("manifest serializes"),
        )
        .expect("manifest writes");
        std::fs::write(
            bundle_dir.join("manifest.sig.json"),
            serde_json::to_vec_pretty(&envelope).expect("signature serializes"),
        )
        .expect("signature writes");
    }

    fn rewrite_signed_bundle_sequence(fixture: &SignedRelayBundleFixture, sequence: u64) {
        let manifest_path = fixture.bundle_dir.join("manifest.json");
        let mut manifest: ConfigBundleManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        manifest.sequence = sequence;
        manifest.bundle_id = format!("relay-bind-bundle-{sequence}");
        manifest.previous_config_hash = (sequence > 1).then(|| manifest.config_hash.clone());
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
        let kid = private.public().jkt().expect("thumbprint");
        write_bundle_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);
    }

    fn rewrite_signed_bundle_instance_id(
        fixture: &SignedRelayBundleFixture,
        instance_id: Option<&str>,
    ) {
        let manifest_path = fixture.bundle_dir.join("manifest.json");
        let mut manifest: ConfigBundleManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        manifest.acceptance_identity.instance = instance_id.unwrap_or_default().to_string();
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
        let kid = private.public().jkt().expect("thumbprint");
        write_bundle_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);
    }

    fn rewrite_anchor_instance_id(fixture: &SignedRelayBundleFixture, instance_id: &str) {
        let mut anchor: ConfigTrustAnchor = serde_json::from_slice(
            &std::fs::read(&fixture.anchor_path).expect("trust anchor reads"),
        )
        .expect("trust anchor parses");
        anchor.acceptance_identity.instance = instance_id.to_string();
        std::fs::write(
            &fixture.anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("trust anchor serializes"),
        )
        .expect("trust anchor writes");
    }

    fn rewrite_signed_bundle_product(fixture: &SignedRelayBundleFixture, product: &str) {
        let manifest_path = fixture.bundle_dir.join("manifest.json");
        let mut manifest: ConfigBundleManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        let (lane, acceptance_product) = if product == "registry-relay" {
            (
                ProductAcceptanceLaneV1::RelayPublic,
                ProductAcceptanceProductV1::RegistryRelay,
            )
        } else {
            (
                ProductAcceptanceLaneV1::Notary,
                ProductAcceptanceProductV1::RegistryNotary,
            )
        };
        manifest.acceptance_identity.lane = lane;
        manifest.acceptance_identity.product = acceptance_product;
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
        let kid = private.public().jkt().expect("thumbprint");
        write_bundle_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);

        let mut anchor: ConfigTrustAnchor = serde_json::from_slice(
            &std::fs::read(&fixture.anchor_path).expect("trust anchor reads"),
        )
        .expect("trust anchor parses");
        anchor.acceptance_identity.lane = lane;
        anchor.acceptance_identity.product = acceptance_product;
        std::fs::write(
            &fixture.anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("trust anchor serializes"),
        )
        .expect("trust anchor writes");
    }

    fn rewrite_signed_bundle_identity(
        fixture: &SignedRelayBundleFixture,
        mutate: impl FnOnce(&mut ProductAcceptanceIdentityV1),
    ) {
        let manifest_path = fixture.bundle_dir.join("manifest.json");
        let mut manifest: ConfigBundleManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        mutate(&mut manifest.acceptance_identity);
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
        let kid = private.public().jkt().expect("thumbprint");
        write_bundle_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);
    }

    fn rewrite_signed_bundle_and_anchor_identity(
        fixture: &SignedRelayBundleFixture,
        mutate: impl Fn(&mut ProductAcceptanceIdentityV1),
    ) {
        rewrite_signed_bundle_identity(fixture, |identity| mutate(identity));
        let mut anchor: ConfigTrustAnchor = serde_json::from_slice(
            &std::fs::read(&fixture.anchor_path).expect("trust anchor reads"),
        )
        .expect("trust anchor parses");
        mutate(&mut anchor.acceptance_identity);
        std::fs::write(
            &fixture.anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("trust anchor serializes"),
        )
        .expect("trust anchor writes");
    }

    fn relay_bootstrap_config(fixture: &SignedRelayBundleFixture, hash_secret_env: &str) -> String {
        format!(
            r#"{}
config_trust:
  trust_anchor_path: {}
  bundle_path: {}
  antirollback_state_path: {}
"#,
            runtime_config_yaml(hash_secret_env),
            fixture.anchor_path.display(),
            fixture.bundle_dir.display(),
            fixture.state_path.display()
        )
    }

    fn signed_bundle_source(fixture: &SignedRelayBundleFixture) -> ServeConfigSource {
        ServeConfigSource::SignedBundle {
            bundle_dir: fixture.bundle_dir.clone(),
            anchor_path: fixture.anchor_path.clone(),
            state_path: fixture.state_path.clone(),
            expected_lane: None,
        }
    }

    fn test_antirollback_key() -> AntiRollbackKey {
        AntiRollbackKey {
            acceptance_identity: ProductAcceptanceIdentityV1 {
                trust_domain: ProductTrustDomainV1::Governed,
                project: "relay-loader-project".to_string(),
                environment: "lab".to_string(),
                lane: ProductAcceptanceLaneV1::RelayPublic,
                product: ProductAcceptanceProductV1::RegistryRelay,
                stream: "relay-loader-test".to_string(),
                instance: "relay-lab".to_string(),
            },
        }
    }

    fn test_override_pin(mode: ConfigOverrideMode, config_hash: String) -> ConfigOverridePin {
        ConfigOverridePin {
            active: true,
            mode,
            config_hash,
            config_path: None,
            expires_at: Some("2099-07-07T12:00:00Z".to_string()),
            used_at: "2026-07-07T10:00:00Z".to_string(),
            operator: "ops@example.test".to_string(),
            reason: "recover interrupted config override consumption".to_string(),
        }
    }

    fn test_pending_bundle_acceptance(
        state_path: std::path::PathBuf,
        source: registry_platform_ops::ConfigSource,
        state_action: BundleStateAction,
        config_hash: String,
        override_pin: Option<ConfigOverridePin>,
    ) -> PendingBundleAcceptance {
        let signed_source = source == registry_platform_ops::ConfigSource::SignedBundleFile;
        PendingBundleAcceptance {
            state_path,
            key: test_antirollback_key(),
            accepted_anchor: AcceptedAnchorPinV1 {
                digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_string(),
                version: 1,
                threshold: 1,
                enabled_signers: vec!["kid-1".to_string()],
            },
            source,
            bundle_id: signed_source.then(|| "relay-loader-bundle".to_string()),
            bundle_manifest_hash: signed_source.then(|| {
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_string()
            }),
            sequence: signed_source.then_some(1),
            config_hash,
            previous_config_hash: None,
            previous_hash_matched: None,
            signer_kids: if signed_source {
                vec!["kid-1".to_string()]
            } else {
                Vec::new()
            },
            break_glass: matches!(state_action, BundleStateAction::PersistOverridePin),
            state_action,
            override_pin,
            override_path: None,
        }
    }

    fn audit_event_names(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                let envelope: Value = serde_json::from_str(line).expect("audit envelope json");
                envelope["record"]["path"]
                    .as_str()
                    .and_then(|path| path.strip_prefix("/__events/"))
                    .expect("audit event path")
                    .to_string()
            })
            .collect()
    }

    #[tokio::test]
    async fn boot_already_pinned_recovery_does_not_emit_break_glass_used_audit() {
        let dir = tempdir().expect("tempdir");
        let signed_hash = test_hash('b');
        let signed_acceptance = test_pending_bundle_acceptance(
            dir.path().join("signed-state.json"),
            registry_platform_ops::ConfigSource::SignedBundleFile,
            BundleStateAction::AlreadyPinned,
            signed_hash.clone(),
            Some(test_override_pin(
                ConfigOverrideMode::AcceptRollback,
                signed_hash,
            )),
        );
        assert!(!signed_acceptance.emits_break_glass_used_audit());
        let signed_sink = InMemorySink::new();
        let signed_audit = AuditPipeline::from_sink(signed_sink.clone());

        super::write_boot_config_audits(signed_audit.as_ref(), &signed_acceptance)
            .await
            .expect("signed recovery audit writes");

        let signed_lines = signed_sink.snapshot();
        let signed_events = audit_event_names(&signed_lines);
        assert_eq!(signed_events, vec!["config.bundle_accepted"]);
        assert!(!signed_events
            .iter()
            .any(|event| event == "config.break_glass_used"));
        let accepted_envelope: Value =
            serde_json::from_str(&signed_lines[0]).expect("accepted audit envelope json");
        assert_eq!(
            accepted_envelope["record"]["config"]["bundle_id"],
            "relay-loader-bundle"
        );
        assert_eq!(
            accepted_envelope["record"]["config"]["signer_kids"],
            json!(["kid-1"])
        );
        assert_eq!(
            accepted_envelope["record"]["config"]["config_hash"],
            signed_acceptance.config_hash
        );

        let unsigned_hash = test_hash('c');
        let mut unsigned_pin =
            test_override_pin(ConfigOverrideMode::AcceptUnsigned, unsigned_hash.clone());
        unsigned_pin.config_path = Some(
            dir.path()
                .join("unsigned.yaml")
                .to_string_lossy()
                .into_owned(),
        );
        let unsigned_acceptance = test_pending_bundle_acceptance(
            dir.path().join("unsigned-state.json"),
            registry_platform_ops::ConfigSource::LocalFile,
            BundleStateAction::AlreadyPinned,
            unsigned_hash,
            Some(unsigned_pin),
        );
        assert!(!unsigned_acceptance.emits_break_glass_used_audit());
        let unsigned_sink = InMemorySink::new();
        let unsigned_audit = AuditPipeline::from_sink(unsigned_sink.clone());

        super::write_boot_config_audits(unsigned_audit.as_ref(), &unsigned_acceptance)
            .await
            .expect("unsigned recovery audit writes");

        assert!(audit_event_names(&unsigned_sink.snapshot()).is_empty());
    }

    #[tokio::test]
    async fn boot_break_glass_acceptance_emits_break_glass_used_audit() {
        let dir = tempdir().expect("tempdir");
        let signed_hash = test_hash('b');
        let signed_acceptance = test_pending_bundle_acceptance(
            dir.path().join("signed-state.json"),
            registry_platform_ops::ConfigSource::SignedBundleFile,
            BundleStateAction::PersistOverridePin,
            signed_hash.clone(),
            Some(test_override_pin(
                ConfigOverrideMode::AcceptRollback,
                signed_hash,
            )),
        );
        assert!(signed_acceptance.emits_break_glass_used_audit());
        let signed_sink = InMemorySink::new();
        let signed_audit = AuditPipeline::from_sink(signed_sink.clone());

        super::write_boot_config_audits(signed_audit.as_ref(), &signed_acceptance)
            .await
            .expect("signed break-glass audit writes");

        assert_eq!(
            audit_event_names(&signed_sink.snapshot()),
            vec!["config.break_glass_used", "config.bundle_accepted"]
        );

        let unsigned_hash = test_hash('c');
        let mut unsigned_pin =
            test_override_pin(ConfigOverrideMode::AcceptUnsigned, unsigned_hash.clone());
        unsigned_pin.config_path = Some(
            dir.path()
                .join("unsigned.yaml")
                .to_string_lossy()
                .into_owned(),
        );
        let unsigned_acceptance = test_pending_bundle_acceptance(
            dir.path().join("unsigned-state.json"),
            registry_platform_ops::ConfigSource::LocalFile,
            BundleStateAction::PersistOverridePin,
            unsigned_hash,
            Some(unsigned_pin),
        );
        assert!(unsigned_acceptance.emits_break_glass_used_audit());
        let unsigned_sink = InMemorySink::new();
        let unsigned_audit = AuditPipeline::from_sink(unsigned_sink.clone());

        super::write_boot_config_audits(unsigned_audit.as_ref(), &unsigned_acceptance)
            .await
            .expect("unsigned break-glass audit writes");

        assert_eq!(
            audit_event_names(&unsigned_sink.snapshot()),
            vec!["config.break_glass_used"]
        );
    }

    #[tokio::test]
    async fn boot_bundle_acceptance_audit_failure_aborts_before_antirollback_persist() {
        let dir = tempdir().expect("tempdir");
        let state_path = dir.path().join("antirollback.json");
        let acceptance = test_pending_bundle_acceptance(
            state_path.clone(),
            registry_platform_ops::ConfigSource::SignedBundleFile,
            BundleStateAction::Initialize,
            test_hash('d'),
            None,
        );
        let failing_audit = AuditPipeline::from_sink(FailingAuditSink);

        let result = async {
            super::write_boot_config_audits(failing_audit.as_ref(), &acceptance).await?;
            super::persist_bundle_acceptance(&acceptance)?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;

        assert!(result.is_err());
        let err = FileAntiRollbackStore::new(&state_path)
            .load(&acceptance.key)
            .expect_err("state remains absent");
        assert_eq!(err, AntiRollbackStoreError::MissingState);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn boot_listener_bind_failure_preserves_exact_antirollback_state() {
        let _guard = env_lock();
        let env_name = "REGISTRY_RELAY_BIND_FAILURE_AUDIT_HASH_SECRET";
        std::env::set_var(env_name, "registry-relay-bind-failure-secret-32-bytes");
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, env_name);
        let verified = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect("bundle verifies");
        let candidate =
            registry_platform_ops::VerifiedAcceptanceStateV1::from_verified_bundle(&verified)
                .expect("acceptance candidate");
        let store = FileAntiRollbackStore::new(&fixture.state_path);
        let plan = store
            .plan_initialize(&candidate)
            .expect("initial state plan");
        store
            .commit_acceptance(plan, |_| async { Ok::<(), std::convert::Infallible>(()) })
            .await
            .expect("test state initializes");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("held listener binds");
        let occupied_addr = listener.local_addr().expect("listener exposes addr");

        let error = super::run_server(
            signed_bundle_source(&fixture),
            None,
            Some(occupied_addr),
            None,
        )
        .await
        .expect_err("occupied listener rejects startup");

        assert!(
            error
                .to_string()
                .contains("relay.startup.data_listener_address_in_use"),
            "unexpected error: {error}"
        );
        store
            .verify_state(candidate.expectation())
            .expect("listener failure does not change exact state");

        drop(listener);
        std::env::remove_var(env_name);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn direct_verified_bundle_compiles_owned_runtime_without_bootstrap_or_state_mutation() {
        let _guard = env_lock();
        let env_name = "REGISTRY_RELAY_DIRECT_BUNDLE_AUDIT_HASH_SECRET";
        std::env::set_var(env_name, "registry-relay-direct-bundle-secret-32-bytes");
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, env_name);

        let runtime = super::compile_relay_runtime_with_options(
            signed_bundle_source(&fixture),
            None,
            registry_relay::config::LoadOptions {
                initialize_state: true,
            },
        )
        .await
        .expect("verified bundle compiles directly");

        assert!(runtime.config.config_trust.is_none());
        assert_eq!(
            runtime.config_provenance.source,
            ConfigSource::SignedBundleFile
        );
        let acceptance = runtime
            .pending_bundle_acceptance
            .as_ref()
            .expect("direct bundle owns pending acceptance");
        assert_eq!(acceptance.state_action, BundleStateAction::Initialize);
        assert_eq!(acceptance.source, ConfigSource::SignedBundleFile);
        let state_error = FileAntiRollbackStore::new(&fixture.state_path)
            .load(&acceptance.key)
            .expect_err("runtime compilation does not persist acceptance");
        assert_eq!(state_error, AntiRollbackStoreError::MissingState);

        std::env::remove_var(env_name);
    }

    #[test]
    fn direct_bundle_without_instance_id_cannot_initialize_or_start() {
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, "UNUSED_MISSING_INSTANCE_AUDIT_HASH_SECRET");
        rewrite_signed_bundle_instance_id(&fixture, None);
        verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("incomplete acceptance identity fails bundle verification");
        assert!(!fixture.state_path.exists());
    }

    #[test]
    fn product_action_rejects_every_acceptance_identity_mismatch_before_state_access() {
        for dimension in [
            "trust_domain",
            "project",
            "environment",
            "lane",
            "product",
            "stream",
            "instance",
        ] {
            let dir = tempdir().expect("tempdir");
            let fixture = write_signed_relay_bundle(&dir, "UNUSED_IDENTITY_MISMATCH_AUDIT_SECRET");
            rewrite_signed_bundle_identity(&fixture, |identity| match dimension {
                "trust_domain" => identity.trust_domain = ProductTrustDomainV1::Development,
                "project" => identity.project = "other-project".to_string(),
                "environment" => identity.environment = "other-environment".to_string(),
                "lane" => identity.lane = ProductAcceptanceLaneV1::RelayConsultation,
                "product" => {
                    identity.lane = ProductAcceptanceLaneV1::Notary;
                    identity.product = ProductAcceptanceProductV1::RegistryNotary;
                }
                "stream" => identity.stream = "other-stream".to_string(),
                "instance" => identity.instance = "other-instance".to_string(),
                _ => unreachable!(),
            });

            registry_relay::config::loader::load_verified_bundle_with_metadata_for_lane_options(
                &fixture.bundle_dir,
                &fixture.anchor_path,
                &fixture.state_path,
                registry_relay::config::loader::RelayProductLane::Public,
                registry_relay::config::LoadOptions {
                    initialize_state: true,
                },
            )
            .expect_err("identity mismatch fails");
            assert!(
                !fixture.state_path.exists(),
                "{dimension} mismatch accessed state"
            );
        }
    }

    #[test]
    fn product_action_rejects_swapped_canonical_lane_inputs_before_state_access() {
        let public_dir = tempdir().expect("tempdir");
        let public = write_signed_relay_bundle(&public_dir, "UNUSED_PUBLIC_LANE_SWAP_AUDIT_SECRET");
        registry_relay::config::loader::load_verified_bundle_with_metadata_for_lane_options(
            &public.bundle_dir,
            &public.anchor_path,
            &public.state_path,
            registry_relay::config::loader::RelayProductLane::Consultation,
            registry_relay::config::LoadOptions {
                initialize_state: true,
            },
        )
        .expect_err("public input cannot occupy consultation lane");
        assert!(!public.state_path.exists());

        let consultation_dir = tempdir().expect("tempdir");
        let consultation = write_signed_relay_bundle(
            &consultation_dir,
            "UNUSED_CONSULTATION_LANE_SWAP_AUDIT_SECRET",
        );
        rewrite_signed_bundle_and_anchor_identity(&consultation, |identity| {
            identity.lane = ProductAcceptanceLaneV1::RelayConsultation;
        });
        registry_relay::config::loader::load_verified_bundle_with_metadata_for_lane_options(
            &consultation.bundle_dir,
            &consultation.anchor_path,
            &consultation.state_path,
            registry_relay::config::loader::RelayProductLane::Public,
            registry_relay::config::LoadOptions {
                initialize_state: true,
            },
        )
        .expect_err("consultation input cannot occupy public lane");
        assert!(!consultation.state_path.exists());
    }

    #[test]
    fn direct_bundle_without_instance_id_cannot_share_lane_across_instance_anchors() {
        let dir = tempdir().expect("tempdir");
        let fixture =
            write_signed_relay_bundle(&dir, "UNUSED_SHARED_INSTANCE_LANE_AUDIT_HASH_SECRET");
        rewrite_signed_bundle_instance_id(&fixture, None);

        for instance_id in ["relay-instance-one", "relay-instance-two"] {
            rewrite_anchor_instance_id(&fixture, instance_id);
            verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
                .expect_err("incomplete acceptance identity cannot bind to an instance anchor");
            assert!(!fixture.state_path.exists());
        }
    }

    #[test]
    fn direct_verified_bundle_rejects_signature_and_binding_failures_value_free() {
        let signature_dir = tempdir().expect("signature tempdir");
        let signature_fixture =
            write_signed_relay_bundle(&signature_dir, "UNUSED_SIGNATURE_AUDIT_SECRET");
        let signature_path = signature_fixture.bundle_dir.join("manifest.sig.json");
        let mut signature_envelope: ConfigBundleSignatureEnvelope = serde_json::from_slice(
            &std::fs::read(&signature_path).expect("signature envelope reads"),
        )
        .expect("signature envelope parses");
        signature_envelope.signatures[0].sig = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        std::fs::write(
            &signature_path,
            serde_json::to_vec_pretty(&signature_envelope).expect("signature envelope serializes"),
        )
        .expect("invalid signature writes");
        let signature_verification = verify_config_bundle(
            &signature_fixture.bundle_dir,
            &signature_fixture.anchor_path,
        )
        .expect_err("invalid signature is rejected");
        assert_eq!(
            bundle_verify_rejection_code(&signature_verification),
            BundleVerificationCode::REJECTED_SIGNATURE
        );
        let signature_error =
            registry_relay::config::loader::load_verified_bundle_with_metadata_options(
                &signature_fixture.bundle_dir,
                &signature_fixture.anchor_path,
                &signature_fixture.state_path,
                registry_relay::config::LoadOptions {
                    initialize_state: true,
                },
            )
            .expect_err("direct loader rejects invalid signature");
        assert_eq!(signature_error.to_string(), "config validation error");

        let binding_dir = tempdir().expect("binding tempdir");
        let binding_fixture =
            write_signed_relay_bundle(&binding_dir, "UNUSED_BINDING_AUDIT_SECRET");
        let mut anchor: ConfigTrustAnchor = serde_json::from_slice(
            &std::fs::read(&binding_fixture.anchor_path).expect("trust anchor reads"),
        )
        .expect("trust anchor parses");
        anchor.acceptance_identity.instance = "sentinel-private-instance".to_string();
        std::fs::write(
            &binding_fixture.anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("trust anchor serializes"),
        )
        .expect("mismatched trust anchor writes");
        let binding_verification =
            verify_config_bundle(&binding_fixture.bundle_dir, &binding_fixture.anchor_path)
                .expect_err("bundle binding mismatch is rejected");
        assert_eq!(
            bundle_verify_rejection_code(&binding_verification),
            BundleVerificationCode::REJECTED_BINDING
        );
        let binding_error =
            registry_relay::config::loader::load_verified_bundle_with_metadata_options(
                &binding_fixture.bundle_dir,
                &binding_fixture.anchor_path,
                &binding_fixture.state_path,
                registry_relay::config::LoadOptions {
                    initialize_state: true,
                },
            )
            .expect_err("direct loader rejects binding mismatch");
        let rendered = binding_error.to_string();
        assert_eq!(rendered, "config validation error");
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains(binding_fixture.anchor_path.to_string_lossy().as_ref()));
    }

    #[test]
    fn direct_startup_rejects_cross_product_bundle_before_state_access() {
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, "UNUSED_CROSS_PRODUCT_AUDIT_SECRET");
        rewrite_signed_bundle_product(&fixture, "registry-notary");
        let verified = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect("cross-product bundle still verifies against its supplied anchor");
        assert_eq!(
            registry_relay::config::loader::verify_relay_bundle_product_binding(&verified),
            Err(BundleVerificationCode::REJECTED_BINDING)
        );

        let error = registry_relay::config::loader::load_verified_bundle_with_metadata_options(
            &fixture.bundle_dir,
            &fixture.anchor_path,
            &fixture.state_path,
            registry_relay::config::LoadOptions {
                initialize_state: true,
            },
        )
        .expect_err("Relay rejects a bundle for another product");

        assert_eq!(error.to_string(), "config validation error");
        assert!(!fixture.state_path.exists());
    }

    #[test]
    fn bootstrap_startup_rejects_cross_product_bundle_before_fallback_or_state_access() {
        let dir = tempdir().expect("tempdir");
        let fixture =
            write_signed_relay_bundle(&dir, "UNUSED_BOOTSTRAP_CROSS_PRODUCT_AUDIT_SECRET");
        rewrite_signed_bundle_product(&fixture, "registry-notary");
        verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect("cross-product bundle still verifies against its supplied anchor");
        let bootstrap_path = dir.path().join("bootstrap.yaml");
        std::fs::write(
            &bootstrap_path,
            relay_bootstrap_config(&fixture, "UNUSED_BOOTSTRAP_CROSS_PRODUCT_AUDIT_SECRET"),
        )
        .expect("bootstrap config writes");

        let error = registry_relay::config::load_with_metadata_options(
            &bootstrap_path,
            registry_relay::config::LoadOptions {
                initialize_state: true,
            },
        )
        .expect_err("bootstrap startup rejects a bundle for another product");

        assert_eq!(error.to_string(), "config validation error");
        assert!(!fixture.state_path.exists());
    }

    #[tokio::test]
    async fn config_verify_bundle_reports_cross_product_as_binding_before_state_access() {
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, "UNUSED_VERIFY_CROSS_PRODUCT_AUDIT_SECRET");
        rewrite_signed_bundle_product(&fixture, "registry-notary");

        let error = super::run_config_verify_bundle(super::ConfigVerifyBundleCommand {
            bundle_dir: fixture.bundle_dir.clone(),
            anchor_path: fixture.anchor_path.clone(),
            state_path: fixture.state_path.clone(),
        })
        .await
        .expect_err("offline verification rejects a bundle for another product");

        let failure = error
            .downcast_ref::<ProcessStartupFailure>()
            .expect("binding rejection uses the process startup taxonomy");
        assert_eq!(failure.code(), ProcessStartupCode::BUNDLE_BINDING_REJECTED);
        assert!(!fixture.state_path.exists());
    }

    #[test]
    fn direct_verified_bundle_requires_explicit_state_initialization() {
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, "UNUSED_STATE_INITIALIZATION_AUDIT_SECRET");

        let error = registry_relay::config::loader::load_verified_bundle_with_metadata_options(
            &fixture.bundle_dir,
            &fixture.anchor_path,
            &fixture.state_path,
            registry_relay::config::LoadOptions::default(),
        )
        .expect_err("missing state is rejected without initialize-state");

        assert_eq!(error.to_string(), "config validation error");
        assert!(!fixture.state_path.exists());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn direct_verified_bundle_rejects_stale_state_without_break_glass_fallback() {
        let _guard = env_lock();
        let env_name = "REGISTRY_RELAY_STALE_BUNDLE_AUDIT_HASH_SECRET";
        std::env::set_var(env_name, "registry-relay-stale-bundle-secret-32-bytes");
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, env_name);
        let initial_verified = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect("initial bundle verifies");
        let initial = registry_platform_ops::VerifiedAcceptanceStateV1::from_verified_bundle(
            &initial_verified,
        )
        .expect("initial acceptance candidate");
        let store = FileAntiRollbackStore::new(&fixture.state_path);
        let initial_plan = store.plan_initialize(&initial).expect("initial plan");
        store
            .commit_acceptance(initial_plan, |_| async {
                Ok::<(), std::convert::Infallible>(())
            })
            .await
            .expect("initial state commits");

        rewrite_signed_bundle_sequence(&fixture, 2);
        let updated_verified = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect("updated bundle verifies");
        let updated = registry_platform_ops::VerifiedAcceptanceStateV1::from_verified_bundle(
            &updated_verified,
        )
        .expect("update acceptance candidate");
        let update_plan = store
            .plan_acceptance(&updated, None, None)
            .expect("update plan");
        store
            .commit_acceptance(update_plan, |_| async {
                Ok::<(), std::convert::Infallible>(())
            })
            .await
            .expect("updated state commits");

        rewrite_signed_bundle_sequence(&fixture, 1);

        let error = registry_relay::config::loader::load_verified_bundle_with_metadata_options(
            &fixture.bundle_dir,
            &fixture.anchor_path,
            &fixture.state_path,
            registry_relay::config::LoadOptions::default(),
        )
        .expect_err("lower sequence is rejected");

        assert_eq!(error.to_string(), "config validation error");
        let record = store
            .load(&updated.key)
            .expect("accepted state remains readable");
        assert_eq!(record.last_sequence, 2);
        assert_eq!(record.last_config_hash, updated.config_hash);

        std::env::remove_var(env_name);
    }

    #[test]
    fn product_serve_input_retains_verified_runtime_after_bundle_path_changes() {
        let dir = tempdir().expect("tempdir");
        let fixture = write_signed_relay_bundle(&dir, "UNUSED_PRODUCT_SERVE_AUDIT_SECRET");
        let input = registry_relay::config::loader::load_verified_product_action_input(
            &fixture.bundle_dir,
            &fixture.anchor_path,
            registry_relay::config::loader::RelayProductLane::Public,
        )
        .expect("product action input verifies and loads");
        let expected_title = input.runtime().catalog.title.clone();
        let moved_bundle = dir.path().join("bundle-after-verification");
        std::fs::rename(&fixture.bundle_dir, &moved_bundle)
            .expect("verified bundle path becomes unavailable");

        let loaded = input.into_loaded_config();
        assert_eq!(loaded.runtime.catalog.title, expected_title);
        assert_eq!(
            loaded.provenance.source,
            registry_platform_ops::ConfigSource::SignedBundleFile
        );
        assert!(
            loaded.pending_bundle_acceptance.is_none(),
            "serve performs its exact state check at the product-action boundary"
        );
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
    fn synthetic_source_cli_accepts_only_one_closed_plan() {
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "synthetic-source",
            "--plan",
            "/run/registry/synthetic-source-plan.json",
        ]))
        .expect("synthetic-source command parses");

        assert_eq!(
            command,
            CliCommand::SyntheticSource(SyntheticSourceCommand::Serve {
                plan_path: PathBuf::from("/run/registry/synthetic-source-plan.json"),
            })
        );

        let probe = parse_cli_command_from(command_args(&[
            "registry-relay",
            "synthetic-source",
            "probe",
            "--plan",
            "/run/registry/synthetic-source-plan.json",
        ]))
        .expect("synthetic-source probe parses");
        assert_eq!(
            probe,
            CliCommand::SyntheticSource(SyntheticSourceCommand::Probe {
                plan_path: PathBuf::from("/run/registry/synthetic-source-plan.json"),
            })
        );

        for args in [
            vec!["registry-relay", "synthetic-source"],
            vec![
                "registry-relay",
                "synthetic-source",
                "--bind",
                "127.0.0.1:0",
            ],
            vec![
                "registry-relay",
                "synthetic-source",
                "--plan=/tmp/plan.json",
            ],
            vec![
                "registry-relay",
                "synthetic-source",
                "--plan",
                "/tmp/plan.json",
                "--route",
                "/proxy",
            ],
        ] {
            let error = parse_cli_command_from(command_args(&args))
                .expect_err("synthetic-source extension argument is rejected");
            assert_eq!(
                error.to_string(),
                "synthetic-source requires exactly --plan <path>"
            );
        }

        for args in [
            vec!["registry-relay", "synthetic-source", "probe"],
            vec![
                "registry-relay",
                "synthetic-source",
                "probe",
                "--plan=/tmp/plan.json",
            ],
            vec![
                "registry-relay",
                "synthetic-source",
                "probe",
                "--plan",
                "/tmp/plan.json",
                "--url",
                "https://attacker.invalid",
            ],
            vec![
                "registry-relay",
                "synthetic-source",
                "probe",
                "--plan",
                "/tmp/plan.json",
                "--header",
                "Authorization: attacker",
            ],
        ] {
            let error = parse_cli_command_from(command_args(&args))
                .expect_err("synthetic-source probe extension argument is rejected");
            assert_eq!(
                error.to_string(),
                "synthetic-source probe requires exactly --plan <path>"
            );
        }
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
            expected_config_digest,
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
        assert!(expected_config_digest.is_none());
    }

    #[test]
    fn doctor_cli_accepts_a_redacted_expected_config_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let command = parse_cli_command_from(command_args(&[
            "registry-relay",
            "doctor",
            "--expected-config-digest",
            &digest,
        ]))
        .expect("doctor expected digest parses");

        let CliCommand::Doctor {
            expected_config_digest: Some(expected_config_digest),
            ..
        } = command
        else {
            panic!("expected doctor command with config digest");
        };
        assert_eq!(expected_config_digest.as_str(), digest);
        assert_eq!(
            format!("{expected_config_digest:?}"),
            "ExpectedConfigDigest(<configured>)"
        );
        assert!(!format!("{expected_config_digest:?}").contains(&digest));
    }

    #[test]
    fn doctor_cli_rejects_an_invalid_expected_digest_without_echoing_it() {
        let sentinel = "sha256:sentinel-private-config-identity";
        let error = parse_cli_command_from(command_args(&[
            "registry-relay",
            "doctor",
            "--expected-config-digest",
            sentinel,
        ]))
        .expect_err("invalid expected digest is rejected");

        assert_eq!(
            error.to_string(),
            "--expected-config-digest requires a sha256 digest"
        );
        assert!(!error.to_string().contains(sentinel));
    }

    #[test]
    fn doctor_rejects_a_stale_but_valid_config_generation() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("relay.yaml");
        let config = runtime_config_yaml("REGISTRY_RELAY_TEST_GENERATION_AUDIT_HASH");
        std::fs::write(&config_path, &config).expect("config writes");
        let next_generation = ExpectedConfigDigest::parse(&sha256_uri(b"distinct next generation"))
            .expect("test digest parses");

        let report = build_doctor_report(
            &config_path,
            None,
            Some(DeploymentProfile::Local),
            Some(&next_generation),
        );

        assert!(!report.exit_success);
        assert!(report.output["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "relay.config.generation_mismatch"));
        assert!(!report.output["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "relay.config.loaded"));
    }

    #[test]
    fn doctor_verifies_the_expected_config_generation_before_loading() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("relay.yaml");
        let config = runtime_config_yaml("REGISTRY_RELAY_TEST_GENERATION_MATCH_AUDIT_HASH");
        std::fs::write(&config_path, &config).expect("config writes");
        let expected = ExpectedConfigDigest::parse(&sha256_uri(config.as_bytes()))
            .expect("test digest parses");

        let report = build_doctor_report(&config_path, None, None, Some(&expected));

        assert!(report.output["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "relay.config.generation_verified"));
        assert!(report.output["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "relay.config.loaded"));
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
    fn config_schema_declares_optional_consultation_root() {
        let schema = registry_relay::config::schema::document();
        let variants = schema["properties"]["consultation"]["anyOf"]
            .as_array()
            .expect("optional consultation uses alternatives");
        assert!(variants.iter().any(|variant| variant["type"] == "null"));
        assert!(variants
            .iter()
            .any(|variant| { variant["$ref"] == "#/$defs/ConsultationConfig" }));
        assert!(!schema["required"]
            .as_array()
            .expect("required is an array")
            .iter()
            .any(|entry| entry == "consultation"));
    }

    #[test]
    fn consultation_bootstrap_state_cli_is_tombstoned_without_echoing_values() {
        let error = parse_cli_command_from(command_args(&[
            "registry-relay",
            "consultation",
            "bootstrap-state",
            "--migration-database-url-env",
            "postgresql://sentinel-user:sentinel-secret@example.test/state",
        ]))
        .expect_err("raw bootstrap inputs are never accepted");
        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "consultation bootstrap-state is replaced by signed product-action"
        );
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("postgresql://"));
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
            config_source,
            env_file,
            bind_override,
            ..
        } = command
        else {
            panic!("expected serve command");
        };
        assert_eq!(
            config_source,
            ServeConfigSource::LocalFile {
                config_path: std::path::PathBuf::from("/etc/registry-relay/config.yaml")
            }
        );
        assert!(env_file.is_none());
        assert!(bind_override.is_none());

        if let Some(value) = previous_env_file {
            std::env::set_var("REGISTRY_RELAY_ENV_FILE", value);
        }
    }

    #[test]
    fn ordinary_serve_cli_rejects_initialize_flag() {
        let _guard = env_lock();
        let previous_config = std::env::var_os("REGISTRY_RELAY_CONFIG");
        std::env::remove_var("REGISTRY_RELAY_CONFIG");
        let error = parse_cli_command_from(command_args(&[
            "registry-relay",
            "--bundle-dir",
            "/etc/registry-relay/bundle",
            "--anchor-path=/etc/registry-relay/trust-anchor.json",
            "--state-path",
            "/var/lib/registry-relay/antirollback.json",
            "--initialize-state",
        ]))
        .expect_err("ordinary serve has no initialization authority");
        assert!(error.to_string().contains("unknown serve argument"));

        if let Some(value) = previous_config {
            std::env::set_var("REGISTRY_RELAY_CONFIG", value);
        }
    }

    #[test]
    fn product_action_cli_accepts_only_closed_lane_action_pairs() {
        for (lane, expected_lane) in [
            (
                "relay-public",
                registry_relay::config::loader::RelayProductLane::Public,
            ),
            (
                "relay-consultation",
                registry_relay::config::loader::RelayProductLane::Consultation,
            ),
        ] {
            for (action, expected_action) in [
                (PREPARE_STATE_STORE_ACTION, ProductAction::PrepareStateStore),
                (INITIALIZE_STATE_ACTION, ProductAction::InitializeState),
                (PREVIEW_STATE_ACTION, ProductAction::PreviewState),
                (ACCEPT_STATE_ACTION, ProductAction::AcceptState),
                (VERIFY_STATE_ACTION, ProductAction::VerifyState),
                (SERVE_ACTION, ProductAction::Serve),
            ] {
                assert_eq!(
                    parse_cli_command_from(command_args(&[
                        "registry-relay",
                        PRODUCT_ACTION_COMMAND,
                        lane,
                        action,
                    ]))
                    .expect("closed product action parses"),
                    CliCommand::ProductAction(ProductActionCommand {
                        lane: expected_lane,
                        action: expected_action,
                    })
                );
            }
        }
    }

    #[test]
    fn development_action_cli_is_distinct_and_cannot_select_governed_actions() {
        for lane in ["relay-public", "relay-consultation"] {
            for action in [
                PREPARE_STATE_STORE_ACTION,
                INITIALIZE_STATE_ACTION,
                SERVE_ACTION,
            ] {
                assert!(matches!(
                    parse_cli_command_from(command_args(&[
                        "registry-relay",
                        DEVELOPMENT_ACTION_COMMAND,
                        lane,
                        action,
                    ])),
                    Ok(CliCommand::DevelopmentAction(_))
                ));
            }
            for action in [
                PREVIEW_STATE_ACTION,
                ACCEPT_STATE_ACTION,
                VERIFY_STATE_ACTION,
            ] {
                assert!(parse_cli_command_from(command_args(&[
                    "registry-relay",
                    DEVELOPMENT_ACTION_COMMAND,
                    lane,
                    action,
                ]))
                .is_err());
            }
        }
    }

    #[test]
    fn product_action_cli_rejects_lane_swaps_and_raw_argument_escape_hatches() {
        for args in [
            vec![
                "registry-relay",
                PRODUCT_ACTION_COMMAND,
                "registry-relay",
                SERVE_ACTION,
            ],
            vec![
                "registry-relay",
                PRODUCT_ACTION_COMMAND,
                "relay-public",
                "initialize-state",
            ],
            vec![
                "registry-relay",
                PRODUCT_ACTION_COMMAND,
                "relay-public",
                SERVE_ACTION,
                "--bundle-dir",
                "/sentinel/private/bundle",
            ],
        ] {
            let error = parse_cli_command_from(command_args(&args))
                .expect_err("non-canonical product action fails");
            let rendered = error.to_string();
            assert!(!rendered.contains("sentinel"));
            assert!(!rendered.contains("/private/"));
        }
    }

    #[test]
    fn public_lane_cannot_consume_signed_consultation_bootstrap_policy() {
        let mut config: Config = serde_saphyr::from_str(include_str!(
            "../profiles/synthetic-snapshot-exact-person-status/relay-config.example.yaml"
        ))
        .expect("consultation profile config parses");
        config
            .consultation
            .as_mut()
            .expect("profile enables consultation")
            .bootstrap = Some(registry_relay::config::ConsultationBootstrapPolicyConfig {
            migration_database_url_env: "RELAY_MIGRATION_DATABASE_URL".to_string(),
            owner_role: "relay_state_owner".to_string(),
            keyring_maintenance_database_url_env: "RELAY_KEYRING_MAINTENANCE_DATABASE_URL"
                .to_string(),
            keyring_reader_database_url_env: "RELAY_KEYRING_READER_DATABASE_URL".to_string(),
            active_key_id: "epoch-1".to_string(),
            active_write_deadline_unix_ms: 1_900_000_000_000,
            audit_event_retention_ms: 86_400_000,
        });
        assert_eq!(
            registry_relay::config::loader::verify_relay_runtime_lane_binding(
                registry_relay::config::loader::RelayProductLane::Public,
                &config,
            ),
            Err(BundleVerificationCode::REJECTED_BINDING)
        );
        assert_eq!(
            registry_relay::config::loader::verify_relay_runtime_lane_binding(
                registry_relay::config::loader::RelayProductLane::Consultation,
                &config,
            ),
            Ok(())
        );
    }

    #[test]
    fn serve_cli_rejects_missing_or_partial_verified_bundle_source_without_local_fallback() {
        let _guard = env_lock();
        let previous_config = std::env::var_os("REGISTRY_RELAY_CONFIG");
        std::env::set_var(
            "REGISTRY_RELAY_CONFIG",
            "/sentinel/private/local-fallback.yaml",
        );

        let missing_value =
            parse_cli_command_from(command_args(&["registry-relay", "--bundle-dir"]))
                .expect_err("bundle-dir without a path is rejected");
        assert_eq!(
            missing_value.to_string(),
            "--bundle-dir requires a non-empty path"
        );

        for args in [
            vec!["registry-relay", "--bundle-dir", "/sentinel/private/bundle"],
            vec![
                "registry-relay",
                "--bundle-dir",
                "/sentinel/private/bundle",
                "--anchor-path",
                "/sentinel/private/anchor.json",
            ],
            vec![
                "registry-relay",
                "--anchor-path",
                "/sentinel/private/anchor.json",
                "--state-path",
                "/sentinel/private/state.json",
            ],
        ] {
            let error = parse_cli_command_from(command_args(&args))
                .expect_err("partial signed-bundle source is rejected");
            let rendered = error.to_string();
            assert_eq!(
                rendered,
                "signed-bundle serve requires --bundle-dir, --anchor-path, and --state-path"
            );
            assert!(!rendered.contains("sentinel"));
            assert!(!rendered.contains("local-fallback"));
        }

        if let Some(value) = previous_config {
            std::env::set_var("REGISTRY_RELAY_CONFIG", value);
        } else {
            std::env::remove_var("REGISTRY_RELAY_CONFIG");
        }
    }

    #[test]
    fn serve_cli_rejects_mixed_local_and_verified_bundle_sources_value_free() {
        let error = parse_cli_command_from(command_args(&[
            "registry-relay",
            "--config",
            "/sentinel/private/local.yaml",
            "--bundle-dir",
            "/sentinel/private/bundle",
            "--anchor-path",
            "/sentinel/private/anchor.json",
            "--state-path",
            "/sentinel/private/state.json",
        ]))
        .expect_err("mixed local and signed-bundle sources are rejected");

        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "local config cannot be combined with signed-bundle serve flags"
        );
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("private"));
    }

    #[test]
    fn serve_cli_rejects_verified_bundle_with_local_config_environment() {
        let _guard = env_lock();
        let previous_config = std::env::var_os("REGISTRY_RELAY_CONFIG");
        std::env::set_var(
            "REGISTRY_RELAY_CONFIG",
            "/sentinel/private/local-config.yaml",
        );

        let error = parse_cli_command_from(command_args(&[
            "registry-relay",
            "--bundle-dir",
            "/sentinel/private/bundle",
            "--anchor-path",
            "/sentinel/private/anchor.json",
            "--state-path",
            "/sentinel/private/state.json",
        ]))
        .expect_err("local config environment conflicts with direct bundle");

        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "local config cannot be combined with signed-bundle serve flags"
        );
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("private"));

        if let Some(value) = previous_config {
            std::env::set_var("REGISTRY_RELAY_CONFIG", value);
        } else {
            std::env::remove_var("REGISTRY_RELAY_CONFIG");
        }
    }

    #[cfg(unix)]
    #[test]
    fn serve_cli_rejects_verified_bundle_with_non_unicode_local_config_environment() {
        use std::os::unix::ffi::OsStringExt;

        let _guard = env_lock();
        let previous_config = std::env::var_os("REGISTRY_RELAY_CONFIG");
        std::env::set_var(
            "REGISTRY_RELAY_CONFIG",
            std::ffi::OsString::from_vec(vec![0xff]),
        );

        let error = parse_cli_command_from(command_args(&[
            "registry-relay",
            "--bundle-dir",
            "/sentinel/private/bundle",
            "--anchor-path",
            "/sentinel/private/anchor.json",
            "--state-path",
            "/sentinel/private/state.json",
        ]))
        .expect_err("non-Unicode local config environment conflicts with direct bundle");

        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "local config cannot be combined with signed-bundle serve flags"
        );
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("private"));

        if let Some(value) = previous_config {
            std::env::set_var("REGISTRY_RELAY_CONFIG", value);
        } else {
            std::env::remove_var("REGISTRY_RELAY_CONFIG");
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn direct_bundle_serve_rejects_local_config_from_env_file_value_free() {
        let _guard = env_lock();
        let previous_config = std::env::var_os("REGISTRY_RELAY_CONFIG");
        std::env::remove_var("REGISTRY_RELAY_CONFIG");
        let dir = tempdir().expect("tempdir");
        let env_file = dir.path().join("relay.env");
        std::fs::write(
            &env_file,
            "REGISTRY_RELAY_CONFIG=/sentinel/private/local-config.yaml\n",
        )
        .expect("env file writes");

        let error = super::run_server(
            ServeConfigSource::SignedBundle {
                bundle_dir: PathBuf::from("/sentinel/private/bundle"),
                anchor_path: PathBuf::from("/sentinel/private/anchor.json"),
                state_path: PathBuf::from("/sentinel/private/state.json"),
                expected_lane: None,
            },
            Some(env_file),
            None,
            None,
        )
        .await
        .expect_err("env-file local config conflicts with direct bundle");

        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "local config cannot be combined with signed-bundle serve flags"
        );
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("private"));

        if let Some(value) = previous_config {
            std::env::set_var("REGISTRY_RELAY_CONFIG", value);
        } else {
            std::env::remove_var("REGISTRY_RELAY_CONFIG");
        }
    }

    #[test]
    fn verified_bundle_serve_source_debug_is_value_free() {
        let source = ServeConfigSource::SignedBundle {
            bundle_dir: PathBuf::from("/sentinel/private/bundle"),
            anchor_path: PathBuf::from("/sentinel/private/anchor.json"),
            state_path: PathBuf::from("/sentinel/private/state.json"),
            expected_lane: None,
        };

        let rendered = format!("{source:?}");
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("private"));
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
            config_source,
            env_file,
            bind_override,
            ..
        } = command
        else {
            panic!("expected serve command");
        };
        assert_eq!(
            config_source,
            ServeConfigSource::LocalFile {
                config_path: std::path::PathBuf::from("/etc/registry-relay/config.yaml")
            }
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
                relay_config_value_classification(&["config_trust", key], &json!("sensitive")),
                ConfigValueClassification::Secret,
                "{key} should be classified as secret"
            );
        }
    }

    #[test]
    fn consultation_root_certificate_path_is_topology_redacted() {
        let marker = "/private/deployment/topology/consultation-root.pem";
        assert_eq!(
            relay_config_value_classification(
                &["consultation", "state_plane", "root_certificate_path"],
                &json!(marker),
            ),
            ConfigValueClassification::TopologySensitive
        );
        let resolved = redacted_resolved_config(&format!(
            "consultation:\n  state_plane:\n    root_certificate_path: {marker}\n"
        ))
        .expect("test YAML resolves");
        let rendered = serde_json::to_string(&resolved).expect("redacted config renders");
        assert!(!rendered.contains(marker));
    }

    #[test]
    fn consultation_is_explicitly_restart_only_in_config_explanations() {
        let classes = relay_live_apply_classes();
        let consultation = classes
            .iter()
            .find(|entry| entry["path"] == "consultation")
            .expect("consultation classification is present");
        assert_eq!(consultation["class"], "restart_required");
        let audit = classes
            .iter()
            .find(|entry| entry["path"] == "audit")
            .expect("audit classification is present");
        assert_eq!(audit["class"], "restart_required");
    }

    #[test]
    fn consultation_required_env_report_names_references_without_values() {
        let _guard = env_lock();
        let names = [
            "REGISTRY_RELAY_DIAGNOSTIC_AUDIT_HASH",
            "REGISTRY_RELAY_DIAGNOSTIC_PASSWORD",
            "REGISTRY_RELAY_DIAGNOSTIC_PSEUDONYM",
            "REGISTRY_RELAY_DIAGNOSTIC_STATE_DATABASE",
            "REGISTRY_RELAY_DIAGNOSTIC_USERNAME",
        ];
        for name in names {
            std::env::remove_var(name);
        }
        std::env::set_var(
            "REGISTRY_RELAY_DIAGNOSTIC_STATE_DATABASE",
            "secret-value-must-not-leak",
        );
        let config: Config = serde_saphyr::from_str(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
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
  hash_secret_env: REGISTRY_RELAY_DIAGNOSTIC_AUDIT_HASH
consultation:
  authorized_workload:
    audience: relay-consultation
    client_claim_selector: azp
    client_value: registry-notary
    principal_id: registry-notary
  state_plane:
    database_url_env: REGISTRY_RELAY_DIAGNOSTIC_STATE_DATABASE
    chain_key_epoch_id: chain-epoch-1
    serving_fence_lock_key: 7221091441
    audit_pseudonym_keyring_lock_key: 7221091442
  audit_pseudonym_materials:
    - key_id: epoch-a
      source:
        provider: environment
        name: REGISTRY_RELAY_DIAGNOSTIC_PSEUDONYM
  source_credentials:
    - type: basic
      ref: source-reader
      generation: 1
      username_env: REGISTRY_RELAY_DIAGNOSTIC_USERNAME
      password_env: REGISTRY_RELAY_DIAGNOSTIC_PASSWORD
"#,
        )
        .expect("diagnostic consultation config parses");

        let report = required_env_report(&config);
        let reported_names = report
            .iter()
            .map(|entry| entry["name"].as_str().expect("name is a string"))
            .collect::<Vec<_>>();
        assert_eq!(reported_names, names);
        assert!(report
            .iter()
            .all(|entry| entry["classification"] == "secret"));
        assert_eq!(report[3]["status"], "present");
        let rendered = serde_json::to_string(&report).expect("report renders");
        assert!(!rendered.contains("secret-value-must-not-leak"));

        for name in names {
            std::env::remove_var(name);
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
                relay_config_value_classification(&["config_trust", key], &json!("MFkwEw...")),
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

        assert_eq!(err.to_string(), "--state-path is required");
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
        let url = format!("http://{addr}/healthz");
        let peer = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("test peer accepts");
            drop(connection);
        });

        let err = run_healthcheck(&url, Duration::from_millis(200))
            .await
            .expect_err("healthcheck fails");
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .expect("healthcheck contacts the test peer")
            .expect("test peer joins");
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
            err.downcast_ref::<ReportedConfigLoadFailure>().is_some(),
            "unexpected error: {err}"
        );
        let rendered = err.to_string();
        assert_eq!(
            rendered, "configuration load failure was already reported",
            "loader boundary must remain value-free"
        );
        for forbidden in [
            "deployment.profile_undeclared",
            "set deployment.profile: local for development",
            "production/evidence_grade",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "loader boundary leaked profile-local detail {forbidden:?}: {rendered}"
            );
        }
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
    fn one_shot_product_actions_do_not_construct_runtime_credentials_or_sources() {
        let source = include_str!("main.rs");
        let one_shots = source
            .split("async fn run_product_action")
            .nth(1)
            .and_then(|tail| tail.split("async fn run_config_verify_bundle").next())
            .expect("product-action implementation remains inspectable");
        for forbidden in [
            "build_auth(",
            "IngestRegistry::from_config",
            "run_initial_ingest",
            "spawn_refresh_tasks",
            "ConsultationService::activate",
        ] {
            assert!(
                !one_shots.contains(forbidden),
                "one-shot action constructed forbidden runtime capability: {forbidden}"
            );
        }
    }

    #[test]
    fn server_shutdown_releases_consultation_fence_before_refresh_join() {
        let source = include_str!("main.rs");
        let run_server = source
            .split("async fn run_server")
            .nth(1)
            .and_then(|tail| tail.split("async fn run_openapi").next())
            .expect("run_server body is present");
        let refresh_cancel = run_server
            .find("refresh_shutdown.cancel()")
            .expect("refresh cancellation is present");
        let consultation_shutdown = run_server
            .find("let consultation_shutdown:")
            .expect("consultation shutdown is present");
        let refresh_join = run_server
            .find("refresh_tasks.join_next()")
            .expect("refresh join is present");
        let audit_flush = run_server
            .find("runtime.audit_sink.flush()")
            .expect("final audit flush is present");

        assert!(refresh_cancel < consultation_shutdown);
        assert!(consultation_shutdown < refresh_join);
        assert!(refresh_join < audit_flush);
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

        let profile = build_audit_chain_profile(&config).expect("audit profile builds");
        let sink = build_audit_sink(&config, profile).expect("audit sink builds");
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
        let profile = build_audit_chain_profile(&config).expect("audit profile builds");
        let sink = build_audit_sink(&config, profile).expect("audit sink builds");
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

        assert!(
            !dir.path().join("audit.jsonl.anchor.json").exists(),
            "recovery no longer writes a local completeness anchor"
        );
        assert!(
            break_envelope["prev_hash"].is_string(),
            "break event remains chained to the last good local tail"
        );
    }
}
