// SPDX-License-Identifier: Apache-2.0
//! Registry Notary process entrypoint.

mod serve;

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use registry_config_report::{
    ConfigValueClassification, LiveApplyClass, ReportStatus, RequiredEnvStatus, TrustedValueSource,
    PLATFORM_CONTEXT_CONSTRAINTS_CONTRACT_V1,
    PLATFORM_CONTEXT_CONSTRAINTS_HASH_MATERIAL_CONTRACT_V1,
};
use registry_notary_core::deployment::{
    evaluate_gates, gate_severity_for_profile, DeploymentFindingStatus, DeploymentProfile,
    EvaluatedFinding, FINDING_SOURCE_BINDING_NO_MATCHING_POLICY,
};
use registry_notary_core::{
    deprecated_config_fields, ConfigAuditEvent, ConfigTrustConfig, EvidenceAuthMode,
    Oauth2ClientCredentialsSourceAuthConfig, RegistryNotaryAdminListenerMode,
    SigningKeyProviderConfig, SourceAuthConfig, SourceConnectorKind,
    StandaloneRegistryNotaryConfig,
};
use registry_notary_server::{
    compile_notary_runtime_with_provenance, notary_router_from_runtime,
    notary_routers_from_runtime, openapi_document, EvidenceIssuerRegistry,
};
use registry_platform_config::{
    expand_config_env_vars, reject_deprecated_config_fields, verify_config_bundle,
    ConfigBundleError, VerifiedConfigBundle,
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, PublicJwk};
use registry_platform_httputil::{url as httputil_url, FetchUrlPolicy};
use registry_platform_ops::{
    antirollback_key_from_verified_bundle, audit_shipping_target, bundle_verify_rejection_result,
    evaluate_ack_health, load_unsigned_break_glass_or_pin,
    persist_bundle_acceptance as persist_config_bundle_acceptance,
    posture_safe_runtime_config_hash, resolve_bundle_state_action, verify_bundle_state_read_only,
    AuditSinkKind, BundleStateAction, BundleStateRequest, ConfigBootError, ConfigOverrideMode,
    ConfigProvenance, ConfigSource, PendingBundleAcceptance, UnsignedConfigSelection,
};
use serde_json::{json, Value};
use serve::{serve_listener, ServeLimits};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use ulid::Ulid;

const DEFAULT_LOG_FILTER: &str = "info";
const NOTARY_CONFIG_SCHEMA_VERSION: &str = "registry.notary.config.v1";

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the standalone Registry Notary")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// YAML config path.
    #[arg(short, long, env = "REGISTRY_NOTARY_CONFIG", global = true)]
    config: Option<PathBuf>,
    /// Dotenv-style file to load before config validation resolves env vars.
    #[arg(long, env = "REGISTRY_NOTARY_ENV_FILE", global = true)]
    env_file: Option<PathBuf>,
    /// Override already-set process env vars with values from --env-file.
    #[arg(long, global = true)]
    env_file_override: bool,
    /// Override server.bind after config load.
    #[arg(long, env = "REGISTRY_NOTARY_BIND", global = true)]
    bind: Option<SocketAddr>,
    /// Initialize signed config anti-rollback state on first boot.
    #[arg(long, global = true)]
    initialize_state: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the Registry Notary OpenAPI document as JSON.
    Openapi,
    /// Validate config, env-backed secrets, source auth, and VC wiring.
    Doctor {
        /// Fetch OAuth source tokens and run live reachability checks.
        #[arg(long)]
        live: bool,
        /// Target id for record-level live probes. Output is redacted.
        #[arg(long)]
        target_id: Option<String>,
        /// Override the lookup field used by DCI idtype-value probes.
        #[arg(long)]
        target_id_type: Option<String>,
        /// Validate local VC issuing setup. This does not print credentials.
        #[arg(long)]
        issue_demo_vc: bool,
        /// Print resolved config with no secret values in text output.
        /// For JSON output, use `explain-config --format json`.
        #[arg(long)]
        show_expanded_config: bool,
        /// Review-only deployment profile override for JSON doctor findings.
        #[arg(
            long,
            value_parser = ["local", "hosted_lab", "production", "evidence_grade"]
        )]
        profile: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = DoctorOutputFormat::Text)]
        format: DoctorOutputFormat,
    },
    /// Print resolved config and required env vars.
    ExplainConfig {
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExplainConfigOutputFormat::Json)]
        format: ExplainConfigOutputFormat,
    },
    /// Verify governed runtime configuration bundles without applying them.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Generate starter files.
    Init {
        #[command(subcommand)]
        template: InitCommand,
    },
    /// Generate or hash a Registry Notary API key.
    HashApiKey {
        /// Read the API key from stdin.
        #[arg(long)]
        stdin: bool,
        /// Print only sha256:<hex>, useful for automation.
        #[arg(long)]
        hash_only: bool,
        /// Also print the plaintext key when generating one.
        #[arg(long)]
        print_secret: bool,
        /// API key to hash. If omitted, a random key is generated.
        api_key: Option<String>,
    },
    /// Generate a demo Ed25519 issuer JWK for local VC smoke tests.
    DemoIssuerKey {
        /// Key id to embed in the generated JWK.
        #[arg(long, default_value = "did:web:localhost#registry-notary-demo")]
        kid: String,
    },
    /// Probe the local HTTP health endpoint and exit non-zero when unhealthy.
    Healthcheck {
        /// Health endpoint URL.
        #[arg(
            long,
            env = "REGISTRY_NOTARY_HEALTHCHECK_URL",
            default_value = "http://127.0.0.1:8080/healthz"
        )]
        url: String,
        /// Request timeout in milliseconds.
        #[arg(
            long,
            env = "REGISTRY_NOTARY_HEALTHCHECK_TIMEOUT_MS",
            default_value_t = 5000,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        timeout_ms: u64,
    },
    /// Run the internal CEL worker line protocol.
    #[cfg(feature = "registry-notary-cel")]
    #[command(hide = true)]
    CelWorker,
    /// Print machine-readable build metadata and compiled capabilities.
    BuildInfo,
    /// Print a lightweight JSON schema for top-level config discovery.
    Schema,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Verify a Registry Config Bundle directory against local trust and state.
    VerifyBundle(ConfigVerifyBundleArgs),
}

#[derive(Debug, Clone, ClapArgs)]
struct ConfigVerifyBundleArgs {
    /// Bundle directory containing manifest.json, manifest.sig.json, and config files.
    #[arg(long)]
    bundle_dir: PathBuf,
    /// Trust anchor JSON path.
    #[arg(long)]
    anchor_path: PathBuf,
    /// Anti-rollback state JSON path.
    #[arg(long)]
    state_path: PathBuf,
}

#[derive(Debug, Subcommand)]
enum InitCommand {
    /// Generate a generic DCI source starter skeleton.
    Dci {
        /// Output directory for generated files.
        #[arg(long, default_value = ".")]
        output: PathBuf,
        /// DCI upstream base URL.
        #[arg(long, default_value = "https://dci.example.test")]
        base_url: String,
        /// DCI OAuth token URL.
        #[arg(long, default_value = "https://dci.example.test/oauth2/client/token")]
        token_url: String,
        /// DCI lookup field used by idtype-value queries.
        #[arg(long, default_value = "SUBJECT_ID")]
        lookup_field: String,
        /// Claim id to generate.
        #[arg(long, default_value = "dci-record-exists")]
        claim_id: String,
        /// Human-readable claim title.
        #[arg(long, default_value = "DCI record exists")]
        claim_title: String,
        /// Include local VC issuer wiring and a generated issuer key.
        #[arg(long)]
        demo_issuer: bool,
        /// Create .env.local with generated local secrets.
        #[arg(long, alias = "write-local-secrets")]
        with_env_file: bool,
        /// Overwrite generated files if they already exist.
        #[arg(long)]
        force: bool,
        /// Print generated local secrets to stdout.
        #[arg(long)]
        print_secrets: bool,
    },
}

#[derive(Debug, Default, Clone)]
struct EnvFileReport {
    loaded: BTreeSet<String>,
    skipped_existing: BTreeSet<String>,
}

impl EnvFileReport {
    fn contains(&self, key: &str) -> bool {
        self.loaded.contains(key) || self.skipped_existing.contains(key)
    }
}

#[derive(Debug)]
struct EnvFileError {
    line: usize,
    reason: String,
}

impl fmt::Display for EnvFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid env file at line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for EnvFileError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DoctorOutputFormat {
    Text,
    Json,
}

impl fmt::Display for DoctorOutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => f.write_str("text"),
            Self::Json => f.write_str("json"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExplainConfigOutputFormat {
    Json,
    Text,
}

impl fmt::Display for ExplainConfigOutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Text => f.write_str("text"),
        }
    }
}

#[derive(Debug)]
struct Diagnostic {
    ok: bool,
    warning: bool,
    label: String,
    action: Option<String>,
    report_code: Option<String>,
    report_severity: Option<&'static str>,
}

impl Diagnostic {
    fn ok(label: impl Into<String>) -> Self {
        Self {
            ok: true,
            warning: false,
            label: label.into(),
            action: None,
            report_code: None,
            report_severity: None,
        }
    }

    fn warn(label: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            ok: true,
            warning: true,
            label: label.into(),
            action: Some(action.into()),
            report_code: None,
            report_severity: None,
        }
    }

    fn warn_with_code(
        label: impl Into<String>,
        action: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            ok: true,
            warning: true,
            label: label.into(),
            action: Some(action.into()),
            report_code: Some(code.into()),
            report_severity: Some("warning"),
        }
    }

    fn fail(label: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            ok: false,
            warning: false,
            label: label.into(),
            action: Some(action.into()),
            report_code: None,
            report_severity: None,
        }
    }

    fn deployment_finding(finding: &EvaluatedFinding, profile: Option<DeploymentProfile>) -> Self {
        let severity = finding.severity.as_str();
        let label = deployment_finding_label(finding, profile);
        let action = deployment_finding_action(finding);
        Self {
            ok: !matches!(severity, "startup_fail" | "readiness_fail")
                || finding.status == DeploymentFindingStatus::Waived,
            warning: !matches!(severity, "startup_fail" | "readiness_fail")
                || finding.status == DeploymentFindingStatus::Waived,
            label,
            action: Some(action),
            report_code: Some(finding.id.clone()),
            report_severity: Some(severity),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ERROR {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let env_report = load_env_file_arg(args.env_file.as_deref(), args.env_file_override)?;
    match args.command {
        None => {
            let config_path = required_config_path(args.config.as_deref())?;
            run_server(config_path, args.bind, args.initialize_state).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Openapi) => {
            println!("{}", serde_json::to_string_pretty(&openapi_document())?);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Doctor {
            live,
            target_id,
            target_id_type,
            issue_demo_vc,
            show_expanded_config,
            profile,
            format,
        }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            let ok = doctor(
                config_path,
                &env_report,
                args.bind,
                DoctorOptions {
                    live,
                    target_id,
                    target_id_type,
                    issue_demo_vc,
                    show_expanded_config,
                    profile_override: profile,
                    format,
                },
            )
            .await?;
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Some(Command::ExplainConfig { format }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            explain_config(config_path, &env_report, args.bind, format)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Config {
            command: ConfigCommand::VerifyBundle(verify_args),
        }) => {
            config_verify_bundle(verify_args).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Init { template }) => {
            match template {
                InitCommand::Dci {
                    output,
                    base_url,
                    token_url,
                    lookup_field,
                    claim_id,
                    claim_title,
                    demo_issuer,
                    with_env_file,
                    force,
                    print_secrets,
                } => init_dci(
                    &output,
                    InitDciOptions {
                        base_url,
                        token_url,
                        lookup_field,
                        claim_id,
                        claim_title,
                        demo_issuer,
                        with_env_file,
                        force,
                        print_secrets,
                    },
                )?,
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::HashApiKey {
            stdin,
            hash_only,
            print_secret,
            api_key,
        }) => {
            hash_api_key(stdin, hash_only, print_secret, api_key)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::DemoIssuerKey { kid }) => {
            println!("{}", demo_issuer_jwk(&kid)?);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Healthcheck { url, timeout_ms }) => {
            run_healthcheck(&url, Duration::from_millis(timeout_ms)).await?;
            println!("registry-notary healthcheck ok");
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(feature = "registry-notary-cel")]
        Some(Command::CelWorker) => {
            registry_notary_server::cel_worker::run_stdio_worker();
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::BuildInfo) => {
            println!("{}", serde_json::to_string_pretty(&build_info())?);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Schema) => {
            println!("{}", serde_json::to_string_pretty(&lightweight_schema())?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn run_server(
    config_path: &Path,
    bind_override: Option<SocketAddr>,
    initialize_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing()?;

    let loaded = load_server_config(config_path, initialize_state)?;
    let mut config = loaded.config;
    apply_bind_override(&mut config, bind_override);
    let bind = config.server.bind;
    let admin_mode = config.server.admin_listener.mode;
    let admin_bind = config.server.admin_listener.bind;
    let serve_limits = ServeLimits::from_config(&config.server);
    let runtime = compile_notary_runtime_with_provenance(
        config,
        loaded.config_source,
        loaded.config_provenance.clone(),
    )?;
    match admin_mode {
        RegistryNotaryAdminListenerMode::Dedicated => {
            let public_listener = tokio::net::TcpListener::bind(bind).await?;
            let public_addr: SocketAddr = public_listener.local_addr()?;
            let admin_listener = tokio::net::TcpListener::bind(admin_bind).await?;
            let admin_addr: SocketAddr = admin_listener.local_addr()?;
            emit_and_persist_boot_acceptance(&runtime, loaded.pending_bundle_acceptance.as_ref())
                .await?;
            let routers = notary_routers_from_runtime(runtime);
            tracing::info!(
                %public_addr,
                %admin_addr,
                build_features = ?compiled_build_features(),
                "registry notary listening with dedicated admin listener"
            );

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                shutdown_signal().await;
                let _ = shutdown_tx.send(true);
            });
            let public_shutdown = shutdown_when_signaled(shutdown_rx.clone());
            let admin_shutdown = shutdown_when_signaled(shutdown_rx);
            let public = serve_listener(
                public_listener,
                routers
                    .public
                    .layer(TraceLayer::new_for_http().make_span_with(http_trace_span)),
                serve_limits,
                public_shutdown,
            );
            let admin = serve_listener(
                admin_listener,
                routers
                    .admin
                    .layer(TraceLayer::new_for_http().make_span_with(http_trace_span)),
                serve_limits,
                admin_shutdown,
            );
            tokio::try_join!(public, admin)?;
        }
        RegistryNotaryAdminListenerMode::SharedWithPublic => {
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let local_addr: SocketAddr = listener.local_addr()?;
            emit_and_persist_boot_acceptance(&runtime, loaded.pending_bundle_acceptance.as_ref())
                .await?;
            let app = notary_router_from_runtime(runtime)
                .layer(TraceLayer::new_for_http().make_span_with(http_trace_span));
            tracing::info!(
                %local_addr,
                build_features = ?compiled_build_features(),
                "registry notary listening"
            );

            serve_listener(listener, app, serve_limits, shutdown_signal()).await?;
        }
        RegistryNotaryAdminListenerMode::Disabled => {
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let local_addr: SocketAddr = listener.local_addr()?;
            emit_and_persist_boot_acceptance(&runtime, loaded.pending_bundle_acceptance.as_ref())
                .await?;
            let app = notary_routers_from_runtime(runtime)
                .public
                .layer(TraceLayer::new_for_http().make_span_with(http_trace_span));
            tracing::info!(
                %local_addr,
                build_features = ?compiled_build_features(),
                "registry notary listening without admin listener"
            );

            serve_listener(listener, app, serve_limits, shutdown_signal()).await?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct LoadedServerConfig {
    config: StandaloneRegistryNotaryConfig,
    config_source: ConfigSource,
    config_provenance: Option<ConfigProvenance>,
    pending_bundle_acceptance: Option<PendingBundleAcceptance>,
}

#[derive(Debug)]
struct ParsedConfigDocument {
    config: StandaloneRegistryNotaryConfig,
    value: Value,
    admin_listener_present: bool,
}

fn bundle_acceptance_audit(acceptance: &PendingBundleAcceptance) -> ConfigAuditEvent {
    ConfigAuditEvent {
        action: "boot".to_string(),
        source: acceptance.source.as_posture_str().to_string(),
        bundle_id: acceptance.bundle_id.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        product_validation_result: "accepted".to_string(),
        apply_result: "applied".to_string(),
        posture_result: "accepted".to_string(),
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
    }
}

async fn emit_boot_config_audits(
    runtime: &registry_notary_server::NotaryRuntimeSnapshot,
    acceptance: &PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error>> {
    if acceptance.emits_break_glass_used_audit() {
        runtime
            .emit_config_boot_audit(
                "config.break_glass_used",
                break_glass_used_audit(acceptance)?,
            )
            .await?;
    }
    if acceptance.source == ConfigSource::SignedBundleFile {
        runtime
            .emit_config_boot_audit(
                "config.bundle_accepted",
                bundle_acceptance_audit(acceptance),
            )
            .await?;
    }
    Ok(())
}

fn break_glass_used_audit(
    acceptance: &PendingBundleAcceptance,
) -> Result<ConfigAuditEvent, Box<dyn std::error::Error>> {
    let pin = acceptance
        .override_pin
        .as_ref()
        .ok_or("break-glass acceptance is missing override pin")?;
    Ok(ConfigAuditEvent {
        action: "boot".to_string(),
        source: acceptance.source.as_posture_str().to_string(),
        bundle_id: acceptance.bundle_id.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        product_validation_result: "accepted".to_string(),
        apply_result: "applied".to_string(),
        posture_result: "accepted".to_string(),
        applied: true,
        restart_required: false,
        change_classes: Vec::new(),
        break_glass: true,
        break_glass_approval_reference: None,
        break_glass_approved_by: Some(pin.operator.clone()),
        break_glass_reason_hash: Some(sha256_hash(&pin.reason)),
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
    })
}

fn rfc3339_unix(value: &str) -> Option<u64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
}

fn persist_bundle_acceptance(
    acceptance: &PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error>> {
    persist_config_bundle_acceptance(acceptance)?;
    Ok(())
}

fn persist_after_successful_boot_audit(
    acceptance: &PendingBundleAcceptance,
    audit_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    audit_result?;
    persist_bundle_acceptance(acceptance)
}

async fn emit_and_persist_boot_acceptance(
    runtime: &registry_notary_server::NotaryRuntimeSnapshot,
    acceptance: Option<&PendingBundleAcceptance>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(acceptance) = acceptance else {
        return Ok(());
    };
    let audit_result = emit_boot_config_audits(runtime, acceptance).await;
    persist_after_successful_boot_audit(acceptance, audit_result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Text,
    Json,
}

fn log_format_from_env() -> Result<LogFormat, String> {
    match std::env::var("REGISTRY_NOTARY_LOG_FORMAT")
        .unwrap_or_else(|_| "text".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "text" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        value => Err(format!(
            "REGISTRY_NOTARY_LOG_FORMAT must be 'text' or 'json', got '{value}'"
        )),
    }
}

fn default_log_filter() -> &'static str {
    DEFAULT_LOG_FILTER
}

fn log_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_log_filter()))
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    let result = match log_format_from_env()? {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(log_env_filter())
            .try_init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(log_env_filter())
            .try_init(),
    };
    if let Err(error) = result {
        let message = error.to_string();
        if message.contains("global default trace dispatcher has already been set") {
            return Ok(());
        }
        return Err(std::io::Error::other(format!("failed to initialize tracing: {error}")).into());
    };
    Ok(())
}

fn http_trace_span(request: &Request<Body>) -> tracing::Span {
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or_else(|| request.uri().path());
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        matched_path,
    )
}

async fn shutdown_when_signaled(mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    let _ = shutdown_rx.wait_for(|shutdown| *shutdown).await;
}

async fn config_verify_bundle(
    args: ConfigVerifyBundleArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let verified = match verify_config_bundle(&args.bundle_dir, &args.anchor_path) {
        Ok(verified) => verified,
        Err(error) => {
            let result = bundle_verify_rejection_result(&error);
            print_config_verify_bundle_report(config_verify_bundle_report(
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
    let key = antirollback_key_from_verified_bundle(&verified);
    if let Err(error) = verify_bundle_state_read_only(
        &args.state_path,
        &key,
        verified.manifest.sequence,
        &verified.manifest.config_hash,
        &verified.manifest_hash,
    ) {
        print_config_verify_bundle_report(config_verify_bundle_report(
            "rejected_rollback",
            &verified.manifest.stream_id,
            Some(verified.manifest.bundle_id.clone()),
            Some(verified.manifest.sequence),
            verified.manifest.previous_config_hash.clone(),
            Some(verified.manifest.config_hash.clone()),
            Some(("rejected_rollback", error.to_string())),
        ))?;
        return Err(Box::new(error));
    }
    let config_text = std::str::from_utf8(&verified.config_bytes)?;
    let parsed = match parse_config_document(config_text).and_then(|parsed| {
        validate_signed_bundle_config_document(&parsed)?;
        Ok(parsed)
    }) {
        Ok(parsed) => parsed,
        Err(error) => {
            print_config_verify_bundle_report(config_verify_bundle_report(
                "rejected_validation",
                &verified.manifest.stream_id,
                Some(verified.manifest.bundle_id.clone()),
                Some(verified.manifest.sequence),
                verified.manifest.previous_config_hash.clone(),
                Some(verified.manifest.config_hash.clone()),
                Some(("rejected_validation", error.to_string())),
            ))?;
            return Err(error);
        }
    };
    if let Err(error) =
        compile_notary_runtime_with_provenance(parsed.config, ConfigSource::SignedBundleFile, None)
    {
        print_config_verify_bundle_report(config_verify_bundle_report(
            "rejected_validation",
            &verified.manifest.stream_id,
            Some(verified.manifest.bundle_id.clone()),
            Some(verified.manifest.sequence),
            verified.manifest.previous_config_hash.clone(),
            Some(verified.manifest.config_hash.clone()),
            Some(("rejected_validation", error.to_string())),
        ))?;
        return Err(Box::new(error));
    }
    print_config_verify_bundle_report(config_verify_bundle_report(
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

fn print_config_verify_bundle_report(report: Value) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(&report)?);
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
        "component": "registry-notary",
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

fn path_for_json(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn required_config_path(path: Option<&Path>) -> Result<&Path, Box<dyn std::error::Error>> {
    path.ok_or_else(|| "--config is required for this command".into())
}

fn compiled_build_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "pkcs11") {
        features.push("pkcs11");
    }
    if cfg!(feature = "registry-notary-cel") {
        features.push("registry-notary-cel");
    }
    features
}

fn build_info() -> Value {
    json!({
        "package": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "build_features": compiled_build_features(),
        "capabilities": {
            "signing_providers": {
                "local_jwk_env": true,
                "pkcs11": cfg!(feature = "pkcs11"),
            },
            "cel": cfg!(feature = "registry-notary-cel"),
        },
    })
}

async fn run_healthcheck(url: &str, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::Client::builder()
        .timeout(timeout)
        .build()?
        .get(url)
        .send()
        .await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("health endpoint returned HTTP {}", response.status()).into())
    }
}

fn parse_expanded_config(
    raw: &str,
) -> Result<StandaloneRegistryNotaryConfig, Box<dyn std::error::Error>> {
    let parsed = parse_config_document(raw)?;
    validate_config_document(&parsed)?;
    Ok(parsed.config)
}

fn parse_config_document(raw: &str) -> Result<ParsedConfigDocument, Box<dyn std::error::Error>> {
    let expanded = expand_config_env_vars(raw)?;
    let parsed_value = parse_config_value(&expanded)?;
    validate_admin_listener_shape(&parsed_value)?;
    reject_deprecated_config_fields(&parsed_value, &deprecated_config_fields())?;
    let admin_listener_present = server_admin_listener_block_present(&parsed_value);
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(&expanded)?;
    Ok(ParsedConfigDocument {
        config,
        value: parsed_value,
        admin_listener_present,
    })
}

fn validate_config_document(
    parsed: &ParsedConfigDocument,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_config_document_with_mode(parsed, false)
}

fn validate_signed_bundle_config_document(
    parsed: &ParsedConfigDocument,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_config_document_with_mode(parsed, true)
}

fn validate_config_document_with_mode(
    parsed: &ParsedConfigDocument,
    governed_runtime: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = &parsed.config;
    if governed_runtime {
        config.validate_governed_runtime()?;
    } else {
        config.validate()?;
    }
    if admin_listener_default_warning_needed(config, parsed.admin_listener_present) {
        tracing::warn!(
            restore_key = "server.admin_listener.mode",
            "server.admin_listener is absent; admin listener defaults to disabled; set server.admin_listener.mode to shared_with_public or dedicated to enable the admin surface"
        );
    }
    Ok(())
}

fn load_server_config(
    config_path: &Path,
    initialize_state: bool,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(config_path)?;
    let bootstrap = parse_config_document(&raw)?;
    let Some(config_trust) = bootstrap.config.config_trust.as_ref() else {
        validate_config_document(&bootstrap)?;
        return Ok(LoadedServerConfig {
            config: bootstrap.config,
            config_source: ConfigSource::LocalFile,
            config_provenance: None,
            pending_bundle_acceptance: None,
        });
    };

    let verified =
        match verify_config_bundle(&config_trust.bundle_path, &config_trust.trust_anchor_path) {
            Ok(verified) => verified,
            Err(error) => {
                if let Some(loaded) = load_unsigned_break_glass_or_pin_server_config(
                    config_trust,
                    config_trust.break_glass_override_path.as_deref(),
                )? {
                    return Ok(loaded);
                }
                log_bundle_verification_error(&error);
                return Err(Box::<dyn std::error::Error>::from(error));
            }
        };
    match load_verified_bundle_server_config(config_trust, initialize_state, verified) {
        Ok(loaded) => Ok(loaded),
        Err(error) => {
            if let Some(loaded) = load_unsigned_break_glass_or_pin_server_config(
                config_trust,
                config_trust.break_glass_override_path.as_deref(),
            )? {
                return Ok(loaded);
            }
            Err(error)
        }
    }
}

fn load_verified_bundle_server_config(
    config_trust: &ConfigTrustConfig,
    initialize_state: bool,
    verified: VerifiedConfigBundle,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    let key = antirollback_key_from_verified_bundle(&verified);
    let state_decision = resolve_bundle_state_action(BundleStateRequest {
        state_path: &config_trust.antirollback_state_path,
        key: &key,
        sequence: verified.manifest.sequence,
        config_hash: &verified.manifest.config_hash,
        bundle_manifest_hash: &verified.manifest_hash,
        previous_config_hash: verified.manifest.previous_config_hash.as_deref(),
        rollback_override_path: config_trust.break_glass_override_path.as_deref(),
        initialize_state,
    })
    .map_err(map_config_boot_error)?;
    let config_text = std::str::from_utf8(&verified.config_bytes).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "signed config bundle primary config is not UTF-8"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Box::<dyn std::error::Error>::from(error)
    })?;
    let parsed = parse_config_document(config_text).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "signed config bundle primary config failed to parse"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    validate_signed_bundle_config_document(&parsed).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "signed config bundle primary config failed product validation"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    let provenance = ConfigProvenance {
        source: ConfigSource::SignedBundleFile,
        internal_config_hash: verified.manifest.config_hash.clone(),
        posture_config_hash: posture_safe_runtime_config_hash(&parsed.value),
        dynamic_reload_supported: false,
        last_bundle_id: Some(verified.manifest.bundle_id.clone()),
        last_bundle_sequence: Some(verified.manifest.sequence),
        last_bundle_signer_kids: verified.signer_kids.clone(),
        override_pin: state_decision.override_pin.clone(),
        last_apply_result: None,
        last_apply_at: None,
        restart_required: false,
    };
    Ok(LoadedServerConfig {
        config: parsed.config,
        config_source: ConfigSource::SignedBundleFile,
        config_provenance: Some(provenance),
        pending_bundle_acceptance: Some(PendingBundleAcceptance {
            state_path: config_trust.antirollback_state_path.clone(),
            key,
            source: ConfigSource::SignedBundleFile,
            bundle_id: Some(verified.manifest.bundle_id),
            bundle_manifest_hash: Some(verified.manifest_hash),
            sequence: Some(verified.manifest.sequence),
            config_hash: verified.manifest.config_hash,
            previous_config_hash: verified.manifest.previous_config_hash,
            previous_hash_matched: state_decision.previous_hash_matched,
            signer_kids: verified.signer_kids,
            break_glass: matches!(
                state_decision.state_action,
                BundleStateAction::PersistOverridePin
            ),
            state_action: state_decision.state_action,
            override_pin: state_decision.override_pin,
            override_path: state_decision.override_path,
        }),
    })
}

fn load_unsigned_break_glass_or_pin_server_config(
    config_trust: &ConfigTrustConfig,
    override_path: Option<&Path>,
) -> Result<Option<LoadedServerConfig>, Box<dyn std::error::Error>> {
    let Some(selection) = load_unsigned_break_glass_or_pin(
        &config_trust.trust_anchor_path,
        &config_trust.antirollback_state_path,
        override_path,
    )
    .map_err(map_config_boot_error)?
    else {
        return Ok(None);
    };
    load_unsigned_pin_server_config(config_trust, selection).map(Some)
}

fn load_unsigned_pin_server_config(
    config_trust: &ConfigTrustConfig,
    selection: UnsignedConfigSelection,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    let config_text = std::str::from_utf8(&selection.config_bytes).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config is not UTF-8"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Box::<dyn std::error::Error>::from(error)
    })?;
    let parsed = parse_config_document(config_text).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config failed to parse"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    validate_config_document(&parsed).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config failed product validation"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    let override_pin = Some(selection.pin.clone());
    Ok(LoadedServerConfig {
        config: parsed.config,
        config_source: ConfigSource::LocalFile,
        config_provenance: Some(ConfigProvenance {
            source: ConfigSource::LocalFile,
            internal_config_hash: selection.pin.config_hash.clone(),
            posture_config_hash: posture_safe_runtime_config_hash(&parsed.value),
            dynamic_reload_supported: false,
            last_bundle_id: selection.record.last_bundle_id,
            last_bundle_sequence: Some(selection.record.last_sequence),
            last_bundle_signer_kids: Vec::new(),
            override_pin: override_pin.clone(),
            last_apply_result: None,
            last_apply_at: None,
            restart_required: false,
        }),
        pending_bundle_acceptance: Some(PendingBundleAcceptance {
            state_path: config_trust.antirollback_state_path.clone(),
            key: selection.key,
            source: ConfigSource::LocalFile,
            bundle_id: None,
            bundle_manifest_hash: None,
            sequence: None,
            config_hash: selection.pin.config_hash,
            previous_config_hash: None,
            previous_hash_matched: None,
            signer_kids: Vec::new(),
            break_glass: matches!(
                selection.state_action,
                BundleStateAction::PersistOverridePin
            ),
            state_action: selection.state_action,
            override_pin,
            override_path: selection.override_path,
        }),
    })
}

fn log_bundle_verification_error(error: &ConfigBundleError) {
    let result = bundle_verify_rejection_result(error);
    tracing::error!(
        code = "config.bundle_rejected",
        result,
        error = %error,
        "signed config bundle verification failed"
    );
    eprintln!("config.bundle_rejected result={result} error={error}");
}

fn map_config_boot_error(error: ConfigBootError) -> Box<dyn std::error::Error> {
    if let Some(reason) = error.break_glass_invalid_reason() {
        tracing::error!(
            code = "config.break_glass_invalid",
            error = %error,
            reason,
            "config break-glass override rejected"
        );
        eprintln!("config.break_glass_invalid error={error}");
    }
    let result = error.bundle_rejection_result();
    tracing::error!(
        code = "config.bundle_rejected",
        result,
        error = %error,
        "config bundle boot state rejected startup"
    );
    eprintln!("config.bundle_rejected result={result} error={error}");
    Box::new(error)
}

#[derive(Debug)]
struct ConfigShapeError(String);

impl fmt::Display for ConfigShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigShapeError {}

fn parse_config_value(raw: &str) -> Result<Value, serde_norway::Error> {
    serde_norway::from_str(raw)
}

fn validate_admin_listener_shape(value: &Value) -> Result<(), ConfigShapeError> {
    let Some(admin_listener) = value
        .get("server")
        .and_then(Value::as_object)
        .and_then(|server| server.get("admin_listener"))
    else {
        return Ok(());
    };
    if admin_listener.is_object() {
        return Ok(());
    }
    Err(ConfigShapeError(
        "server.admin_listener must be a mapping with accepted mode values: disabled, dedicated, shared_with_public; use server.admin_listener.mode to restore the admin surface".to_string(),
    ))
}

fn server_admin_listener_block_present(value: &Value) -> bool {
    value
        .get("server")
        .and_then(Value::as_object)
        .is_some_and(|server| server.contains_key("admin_listener"))
}

fn admin_listener_default_warning_needed(
    config: &StandaloneRegistryNotaryConfig,
    admin_listener_present: bool,
) -> bool {
    !admin_listener_present
        && config.server.admin_listener.mode == RegistryNotaryAdminListenerMode::Disabled
}

fn load_env_file_arg(
    env_file: Option<&Path>,
    override_existing: bool,
) -> Result<EnvFileReport, Box<dyn std::error::Error>> {
    let Some(path) = env_file else {
        return Ok(EnvFileReport::default());
    };
    let raw = fs::read_to_string(path)?;
    apply_env_file(&raw, override_existing).map_err(Into::into)
}

fn apply_env_file(raw: &str, override_existing: bool) -> Result<EnvFileReport, EnvFileError> {
    let mut report = EnvFileReport::default();
    for (key, value) in parse_env_file(raw)? {
        if std::env::var_os(&key).is_some() && !override_existing {
            report.skipped_existing.insert(key);
        } else {
            std::env::set_var(&key, value);
            report.loaded.insert(key);
        }
    }
    Ok(report)
}

fn parse_env_file(raw: &str) -> Result<Vec<(String, String)>, EnvFileError> {
    let mut values = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return Err(env_file_error(line_no, "expected KEY=VALUE"));
        };
        let key = key.trim();
        if !valid_env_key(key) {
            return Err(env_file_error(line_no, "invalid env var name"));
        }
        values.push((key.to_string(), parse_env_value(value.trim(), line_no)?));
    }
    Ok(values)
}

fn parse_env_value(value: &str, line: usize) -> Result<String, EnvFileError> {
    if let Some(rest) = value.strip_prefix('"') {
        let Some(end) = closing_quote_index(rest, '"', true) else {
            return Err(env_file_error(line, "unterminated double-quoted value"));
        };
        if !rest[end + 1..].trim().is_empty() && !rest[end + 1..].trim().starts_with('#') {
            return Err(env_file_error(line, "unexpected text after quoted value"));
        }
        return Ok(rest[..end]
            .replace("\\n", "\n")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\"));
    }
    if let Some(rest) = value.strip_prefix('\'') {
        let Some(end) = closing_quote_index(rest, '\'', false) else {
            return Err(env_file_error(line, "unterminated single-quoted value"));
        };
        if !rest[end + 1..].trim().is_empty() && !rest[end + 1..].trim().starts_with('#') {
            return Err(env_file_error(line, "unexpected text after quoted value"));
        }
        return Ok(rest[..end].to_string());
    }
    Ok(value
        .split_once(" #")
        .map(|(before, _)| before)
        .unwrap_or(value)
        .trim()
        .to_string())
}

fn closing_quote_index(rest: &str, quote: char, allow_escape: bool) -> Option<usize> {
    let mut chars = rest.char_indices();
    while let Some((idx, ch)) = chars.next() {
        if allow_escape && ch == '\\' {
            let _ = chars.next();
            continue;
        }
        if ch == quote {
            return Some(idx);
        }
    }
    None
}

fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('_') | Some('A'..='Z') | Some('a'..='z'))
        && chars.all(|ch| matches!(ch, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

fn env_file_error(line: usize, reason: &str) -> EnvFileError {
    EnvFileError {
        line,
        reason: reason.to_string(),
    }
}

#[derive(Debug)]
struct DoctorOptions {
    live: bool,
    target_id: Option<String>,
    target_id_type: Option<String>,
    issue_demo_vc: bool,
    show_expanded_config: bool,
    profile_override: Option<String>,
    format: DoctorOutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeploymentProfileReport {
    value: Option<String>,
    source: &'static str,
}

async fn doctor(
    config_path: &Path,
    env_report: &EnvFileReport,
    bind_override: Option<SocketAddr>,
    options: DoctorOptions,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut diagnostics = Vec::new();
    let mut expanded_config = None;
    let mut deployment_profile = DeploymentProfileReport {
        value: options.profile_override.clone(),
        source: if options.profile_override.is_some() {
            "override"
        } else {
            "undeclared"
        },
    };
    let raw = match fs::read_to_string(config_path) {
        Ok(raw) => {
            diagnostics.push(Diagnostic::ok("config file read"));
            raw
        }
        Err(err) => {
            diagnostics.push(Diagnostic::fail(
                format!("config file read failed: {err}"),
                "check --config points to a readable YAML file",
            ));
            render_doctor_output(
                &diagnostics,
                options.format,
                None,
                config_path,
                None,
                None,
                env_report,
            )?;
            return Ok(false);
        }
    };
    let parsed = match parse_expanded_config(&raw) {
        Ok(config) => {
            diagnostics.push(Diagnostic::ok("config YAML parsed and validated"));
            let mut config = config;
            apply_bind_override(&mut config, bind_override);
            Some(config)
        }
        Err(err) => {
            diagnostics.push(Diagnostic::fail(
                format!("config YAML parse or validation failed: {err}"),
                "fix the YAML syntax and field names",
            ));
            None
        }
    };
    let config = match parsed {
        Some(config) => {
            diagnostics.push(Diagnostic::ok("config semantics validated"));
            Some(config)
        }
        None => None,
    };
    if let Some(config) = &config {
        if options.profile_override.is_none() {
            if let Some(profile) = config.deployment.profile {
                deployment_profile = DeploymentProfileReport {
                    value: Some(profile.as_str().to_string()),
                    source: "config",
                };
            }
        }
        let profile_value = deployment_profile
            .value
            .as_deref()
            .and_then(deployment_profile_from_str);
        diagnostics.extend(deployment_profile_diagnostics(config, profile_value));
        diagnostics.extend(local_env_diagnostics(config, env_report));
        diagnostics.extend(holder_binding_diagnostics(config));
        diagnostics.extend(matching_policy_diagnostics(config, profile_value));
        if let Some(diagnostic) = pkcs11_preflight_diagnostic(config) {
            diagnostics.push(diagnostic);
        }
        diagnostics.extend(vc_diagnostics(config, options.issue_demo_vc));
        diagnostics.extend(dci_diagnostics(config, options.target_id_type.as_deref()));
        if options.live {
            diagnostics.extend(
                live_diagnostics(
                    config,
                    options.target_id.as_deref(),
                    options.target_id_type.as_deref(),
                )
                .await,
            );
        }
        if options.show_expanded_config {
            expanded_config = Some(redacted_config(config));
        }
    }
    render_doctor_output(
        &diagnostics,
        options.format,
        expanded_config.as_ref(),
        config_path,
        Some(&raw),
        config.as_ref(),
        env_report,
    )?;
    Ok(diagnostics.iter().all(|diag| diag.ok))
}

fn deployment_profile_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    profile_value: Option<DeploymentProfile>,
) -> Vec<Diagnostic> {
    let input = config.gate_input();
    let evaluation = evaluate_gates(
        profile_value,
        &input,
        &config.deployment.waivers,
        &today_utc_date(),
    );
    evaluation
        .findings
        .iter()
        .map(|finding| Diagnostic::deployment_finding(finding, profile_value))
        .collect()
}

fn deployment_profile_from_str(value: &str) -> Option<DeploymentProfile> {
    match value {
        "local" => Some(DeploymentProfile::Local),
        "hosted_lab" => Some(DeploymentProfile::HostedLab),
        "production" => Some(DeploymentProfile::Production),
        "evidence_grade" => Some(DeploymentProfile::EvidenceGrade),
        _ => None,
    }
}

fn deployment_finding_label(
    finding: &EvaluatedFinding,
    profile: Option<DeploymentProfile>,
) -> String {
    if finding.id == "deployment.profile_undeclared" {
        return "deployment profile is undeclared".to_string();
    }
    if finding.id == "deployment.waiver_expired" {
        if let Some(waiver) = &finding.waiver {
            return format!(
                "deployment waiver for '{}' expired on {}",
                waiver.finding, waiver.expires
            );
        }
        return "deployment waiver expired".to_string();
    }
    let profile = profile
        .map(DeploymentProfile::as_str)
        .unwrap_or("undeclared");
    let status = match finding.status {
        DeploymentFindingStatus::Active => "active",
        DeploymentFindingStatus::Waived => "waived",
    };
    format!(
        "{profile} deployment gate '{}' is {status} at severity {}",
        finding.id,
        finding.severity.as_str()
    )
}

fn deployment_finding_action(finding: &EvaluatedFinding) -> String {
    if finding.id == "deployment.profile_undeclared" {
        return "set deployment.profile or pass --profile for review-only doctor output"
            .to_string();
    }
    if finding.id == "deployment.waiver_expired" {
        return "renew the waiver only after review, or remove it and fix the deployment condition"
            .to_string();
    }
    if finding.status == DeploymentFindingStatus::Waived {
        return "review the active deployment waiver and expiry".to_string();
    }
    "update deployment config or runtime settings to clear the gate".to_string()
}

fn holder_binding_diagnostics(config: &StandaloneRegistryNotaryConfig) -> Vec<Diagnostic> {
    let unbound_profiles = config
        .evidence
        .credential_profiles
        .iter()
        .filter(|(_, profile)| profile.holder_binding.mode == "none")
        .map(|(profile_id, _)| profile_id.as_str())
        .collect::<Vec<_>>();
    if unbound_profiles.is_empty() {
        return Vec::new();
    }
    vec![Diagnostic::warn_with_code(
        format!(
            "credential profile(s) issue unbound SD-JWT VC credentials: {}",
            unbound_profiles.join(", ")
        ),
        "set holder_binding.mode: did with allowed_did_methods: [did:jwk], or keep mode: none only for an explicit bearer-style credential profile",
        "notary.credential_profile.unbound_holder_binding",
    )]
}

fn matching_policy_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    profile_value: Option<DeploymentProfile>,
) -> Vec<Diagnostic> {
    // The deployment gate catalog already covers this finding under any
    // profile that binds it (currently production and evidence_grade); skip
    // the explicit diagnostic there so doctor doesn't double-report the same
    // code. Profiles that leave the gate unbound (local, hosted_lab,
    // undeclared) still need this explicit diagnostic for visibility.
    if gate_severity_for_profile(FINDING_SOURCE_BINDING_NO_MATCHING_POLICY, profile_value).is_some()
    {
        return Vec::new();
    }
    let unconstrained_bindings = config
        .evidence
        .claims
        .iter()
        .flat_map(|claim| {
            claim
                .source_bindings
                .iter()
                .filter(|(_, binding)| binding.matching.lacks_matching_policy())
                .map(move |(binding_id, _)| format!("{}/{binding_id}", claim.id))
        })
        .collect::<Vec<_>>();
    if unconstrained_bindings.is_empty() {
        return Vec::new();
    }
    vec![Diagnostic::warn_with_code(
        format!(
            "claim source binding(s) declare no matching policy or matching gates, so resolution falls back to unrestricted, identifier-only matching: {}",
            unconstrained_bindings.join(", ")
        ),
        "declare a matching: block (policy_id, purpose, relationship, input, requester type, ecosystem binding, or context_constraints gates) on each binding, or accept unrestricted identifier-only resolution knowingly",
        "notary.source_binding.no_matching_policy",
    )]
}

/// Today's date in UTC as a `YYYY-MM-DD` string, for waiver-expiry comparison.
fn today_utc_date() -> String {
    let now = OffsetDateTime::now_utc().date();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

fn pkcs11_preflight_diagnostic(config: &StandaloneRegistryNotaryConfig) -> Option<Diagnostic> {
    let has_active_pkcs11 = config.evidence.signing_keys.values().any(|key| {
        matches!(key.provider, SigningKeyProviderConfig::Pkcs11) && key.status.may_sign()
    });
    if !has_active_pkcs11 {
        return None;
    }
    match EvidenceIssuerRegistry::from_config(&config.evidence) {
        Ok(_) => Some(Diagnostic::ok(
            "PKCS#11 signing providers loaded and self-tested",
        )),
        Err(err) => Some(Diagnostic::fail(
            format!("PKCS#11 signing preflight failed: {err}"),
            "check module_path, token_label, pin_env, key_label, key_id_hex, public_jwk_env, and whether this binary was built with pkcs11",
        )),
    }
}

fn print_diagnostics(diagnostics: &[Diagnostic]) {
    for diag in diagnostics {
        let status = if diag.warning {
            "WARN"
        } else if diag.ok {
            "OK  "
        } else {
            "FAIL"
        };
        println!("{status}  {}", diag.label);
        if let Some(action) = &diag.action {
            println!("     Next action: {action}");
        }
    }
}

fn render_doctor_output(
    diagnostics: &[Diagnostic],
    format: DoctorOutputFormat,
    expanded_config: Option<&Value>,
    config_path: &Path,
    raw_config: Option<&str>,
    config: Option<&StandaloneRegistryNotaryConfig>,
    env_report: &EnvFileReport,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        DoctorOutputFormat::Text => {
            if let Some(config) = expanded_config {
                println!("{}", serde_json::to_string_pretty(config)?);
            }
            print_diagnostics(diagnostics);
        }
        DoctorOutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&doctor_json_report(
                    diagnostics,
                    config_path,
                    raw_config,
                    config,
                    env_report,
                ))?
            );
        }
    }
    Ok(())
}

fn doctor_json_report(
    diagnostics: &[Diagnostic],
    config_path: &Path,
    raw_config: Option<&str>,
    config: Option<&StandaloneRegistryNotaryConfig>,
    env_report: &EnvFileReport,
) -> Value {
    let diagnostics_json = diagnostics
        .iter()
        .map(doctor_json_diagnostic)
        .collect::<Vec<_>>();
    let error_count = diagnostics_json
        .iter()
        .filter(|diag| diag["severity"] == "error")
        .count();
    let warning_count = diagnostics_json
        .iter()
        .filter(|diag| diag["severity"] == "warning")
        .count();
    let mut report = json!({
        "schema_version": "registry.config.diagnostic_report.v1",
        "product": "registry-notary",
        "config_schema_version": NOTARY_CONFIG_SCHEMA_VERSION,
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
        "diagnostics": diagnostics_json,
        "required_env": required_env_report(
            config.map(required_env_vars).unwrap_or_default(),
            env_report,
        ),
        "context_constraints": config
            .map(notary_context_constraints_report)
            .unwrap_or_default(),
        "generated_at": now_rfc3339(),
    });
    if let Some(config) = config {
        report["audit_shipping"] = notary_audit_shipping(config);
    }
    if let Some(raw) = raw_config {
        report["hashes"] = json!({
            "internal_config_hash": sha256_hash(raw),
        });
    }
    report
}

/// Report the audit shipping posture for the doctor diagnostic report. This
/// mirrors the `posture.audit` shipping fields (`sink_type`,
/// `shipping_target_configured`, `shipping_target`, `shipping_health`,
/// `shipping_observed_at`). The target is declared state derived from config via
/// the shared classifier; `shipping_health` is OBSERVED delivery freshness read
/// from the local ack cursor. Unmapped sink strings fall back to
/// [`AuditSinkKind::Unknown`] rather than a silent wildcard.
fn notary_audit_shipping(config: &StandaloneRegistryNotaryConfig) -> Value {
    let (sink_kind, sink_type) = match config.audit.sink.as_str() {
        "stdout" => (AuditSinkKind::Stdout, "stdout"),
        "syslog" => (AuditSinkKind::Syslog, "syslog"),
        "file" | "jsonl" => (AuditSinkKind::LocalFile, "file"),
        _ => (AuditSinkKind::Unknown, "unknown"),
    };
    let (shipping_target_configured, shipping_target) =
        audit_shipping_target(sink_kind, config.deployment.evidence.audit_offhost_shipping);
    // Read the local ack cursor for observed freshness. Health is null unless a
    // shipping target is actually configured; observed_at echoes the cursor's
    // acked_at when one was read.
    let observation = evaluate_ack_health(
        config.deployment.evidence.audit_ack_cursor_path(),
        SystemTime::now(),
        config.deployment.evidence.audit_ack_max_age(),
    );
    let shipping_health = if shipping_target_configured {
        Value::from(observation.health.as_str())
    } else {
        Value::Null
    };
    let shipping_observed_at = observation.acked_at.map_or(Value::Null, Value::from);
    json!({
        "sink_type": sink_type,
        "shipping_target_configured": shipping_target_configured,
        "shipping_target": shipping_target,
        "shipping_health": shipping_health,
        "shipping_observed_at": shipping_observed_at,
    })
}

fn doctor_json_diagnostic(diagnostic: &Diagnostic) -> Value {
    let (severity, code) = if let (Some(severity), Some(code)) = (
        diagnostic.report_severity,
        diagnostic.report_code.as_deref(),
    ) {
        (shared_severity(severity), code)
    } else if diagnostic.warning {
        ("warning", "warning")
    } else if diagnostic.ok {
        ("info", "ok")
    } else {
        ("error", "failed")
    };
    let message = if let Some(action) = &diagnostic.action {
        format!("{} Next action: {action}", diagnostic.label)
    } else {
        diagnostic.label.clone()
    };
    let value = json!({
        "severity": severity,
        "code": code,
        "message": message,
    });
    value
}

fn shared_severity(severity: &str) -> &'static str {
    match severity {
        "startup_fail" | "readiness_fail" | "finding_error" | "error" => "error",
        "finding_warn" | "warning" => "warning",
        _ => "info",
    }
}

fn required_env_report(vars: BTreeSet<String>, env_report: &EnvFileReport) -> Vec<Value> {
    vars.into_iter()
        .map(|name| {
            let status = if std::env::var_os(&name).is_some() || env_report.contains(&name) {
                RequiredEnvStatus::Present
            } else {
                RequiredEnvStatus::Missing
            };
            json!({
                "name": name,
                "classification": env_classification(&name).as_str(),
                "status": status.as_str(),
            })
        })
        .collect()
}

fn env_classification(name: &str) -> ConfigValueClassification {
    if name.to_ascii_uppercase().contains("PUBLIC") {
        ConfigValueClassification::Public
    } else {
        ConfigValueClassification::Secret
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC timestamp formats as RFC3339")
}

fn local_env_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    env_report: &EnvFileReport,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for credential in config
        .auth
        .api_keys
        .iter()
        .chain(config.auth.bearer_tokens.iter())
    {
        if let Some(env) = credential.fingerprint.name.as_deref() {
            diagnostics.push(check_fingerprint_env(env, env_report));
        }
    }
    if let Some(secret_env) = &config.audit.hash_secret_env {
        diagnostics.push(check_present_env(
            secret_env,
            env_report,
            "audit hash secret",
        ));
    }
    if matches!(config.audit.sink.as_str(), "file" | "jsonl")
        && !config.deployment.evidence.audit_offhost_shipping
    {
        // Once the operator declares off-host shipping over the local file sink,
        // the deployment gate is cleared and the declared state is visible in
        // the report's audit_shipping section, so this warning is silenced.
        diagnostics.push(Diagnostic::warn(
            "audit file/jsonl sink is local-chain-only",
            "for beta tamper-evidence, ship audit envelopes off-host via stdout/syslog or declare deployment.evidence.audit_offhost_shipping after external shipping is in place",
        ));
    }
    if config.replay.storage == "redis" {
        diagnostics.push(check_present_env(
            &config.replay.redis.url_env,
            env_report,
            "replay Redis URL",
        ));
    }
    if config.credential_status.enabled && config.credential_status.storage == "redis" {
        diagnostics.push(check_present_env(
            &config.credential_status.redis.url_env,
            env_report,
            "credential status Redis URL",
        ));
    }
    if config.federation.enabled {
        diagnostics.push(check_present_env(
            &config.federation.pairwise_subject_hash.secret_env,
            env_report,
            "federation pairwise subject hash secret",
        ));
    }
    for (connection_id, connection) in &config.evidence.source_connections {
        if !connection.token_env.trim().is_empty() {
            diagnostics.push(check_present_env(
                &connection.token_env,
                env_report,
                &format!("source token for {connection_id}"),
            ));
        }
        if let Some(SourceAuthConfig::Oauth2ClientCredentials(auth)) = &connection.source_auth {
            diagnostics.push(check_present_env(
                &auth.client_id_env,
                env_report,
                &format!("OAuth client id for {connection_id}"),
            ));
            diagnostics.push(check_present_env(
                &auth.client_secret_env,
                env_report,
                &format!("OAuth client secret for {connection_id}"),
            ));
        }
    }
    for (key_id, key) in &config.evidence.signing_keys {
        if matches!(key.provider, SigningKeyProviderConfig::LocalJwkEnv) && key.status.may_sign() {
            diagnostics.push(check_local_jwk_env(
                &key.private_jwk_env,
                key_id,
                &key.kid,
                &key.alg,
                env_report,
            ));
        }
        if matches!(key.provider, SigningKeyProviderConfig::LocalJwkEnv)
            && key.status.may_publish()
            && !key.status.may_sign()
        {
            diagnostics.push(check_public_jwk_env(
                &key.public_jwk_env,
                key_id,
                &key.kid,
                &key.alg,
                env_report,
            ));
        }
        if matches!(key.provider, SigningKeyProviderConfig::Pkcs11) && key.status.may_sign() {
            diagnostics.push(check_present_env(
                &key.pin_env,
                env_report,
                &format!("PKCS#11 PIN for signing key {key_id}"),
            ));
        }
        if matches!(key.provider, SigningKeyProviderConfig::Pkcs11) && key.status.may_publish() {
            diagnostics.push(check_public_jwk_env(
                &key.public_jwk_env,
                key_id,
                &key.kid,
                &key.alg,
                env_report,
            ));
        }
    }
    diagnostics
}

fn check_fingerprint_env(env: &str, env_report: &EnvFileReport) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) if valid_sha256_hash(&value) => {
            Diagnostic::ok(format!("{env} is present and valid"))
        }
        Ok(_) => Diagnostic::fail(
            format!("{env} is present but not a sha256:<64 hex> fingerprint"),
            format!("set {env} using `registry-notary hash-api-key --hash-only`"),
        ),
        Err(_) => missing_env_diag(env, env_report, "fingerprint env var"),
    }
}

fn check_present_env(env: &str, env_report: &EnvFileReport, label: &str) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) if !value.trim().is_empty() => {
            Diagnostic::ok(format!("{env} is present for {label}"))
        }
        Ok(_) => Diagnostic::fail(
            format!("{env} is present but empty for {label}"),
            format!("set {env} to a non-empty value"),
        ),
        Err(_) => missing_env_diag(env, env_report, label),
    }
}

fn check_local_jwk_env(
    env: &str,
    key_id: &str,
    expected_kid: &str,
    expected_alg: &str,
    env_report: &EnvFileReport,
) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) => {
            let result = PrivateJwk::parse(&value)
                .and_then(|mut jwk| {
                    if jwk.kid.as_deref().is_some_and(|kid| kid != expected_kid) {
                        return Err(registry_platform_crypto::JwkError::Invalid("kid mismatch"));
                    }
                    if jwk.alg.as_deref().is_some_and(|alg| alg != expected_alg) {
                        return Err(registry_platform_crypto::JwkError::Invalid("alg mismatch"));
                    }
                    jwk.kid = Some(expected_kid.to_string());
                    jwk.alg = Some(expected_alg.to_string());
                    Ok(jwk)
                })
                .map_err(|err| err.to_string())
                .and_then(|jwk| LocalJwkSigner::new(jwk).map_err(|err| err.to_string()));
            match result {
                Ok(_) => Diagnostic::ok(format!("{env} is a usable local JWK for {key_id}")),
                Err(err) => Diagnostic::fail(
                    format!("{env} is not a usable local JWK for {key_id}: {err}"),
                    "generate a local demo key with `registry-notary demo-issuer-key`",
                ),
            }
        }
        Err(_) => missing_env_diag(env, env_report, &format!("local JWK for {key_id}")),
    }
}

fn check_public_jwk_env(
    env: &str,
    key_id: &str,
    expected_kid: &str,
    expected_alg: &str,
    env_report: &EnvFileReport,
) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) => {
            let result = PublicJwk::parse(&value).and_then(|jwk| {
                if jwk.kid.as_deref() != Some(expected_kid) {
                    return Err(registry_platform_crypto::JwkError::Invalid("kid mismatch"));
                }
                if jwk.alg.as_deref() != Some(expected_alg) {
                    return Err(registry_platform_crypto::JwkError::Invalid("alg mismatch"));
                }
                Ok(jwk)
            });
            match result {
                Ok(_) => Diagnostic::ok(format!("{env} is a usable public JWK for {key_id}")),
                Err(err) => Diagnostic::fail(
                    format!("{env} is not a usable public JWK for {key_id}: {err}"),
                    "set it to a public JWK with the configured kid",
                ),
            }
        }
        Err(_) => missing_env_diag(env, env_report, &format!("public JWK for {key_id}")),
    }
}

fn missing_env_diag(env: &str, env_report: &EnvFileReport, label: &str) -> Diagnostic {
    let source_hint = if env_report.contains(env) {
        "it was named in --env-file but not loaded because the process value was absent or empty"
    } else {
        "it was absent from the process and not present in --env-file"
    };
    Diagnostic::fail(
        format!("{env} is missing for {label}"),
        format!("set {env}; {source_hint}"),
    )
}

fn valid_sha256_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn vc_diagnostics(config: &StandaloneRegistryNotaryConfig, issue_demo_vc: bool) -> Vec<Diagnostic> {
    let claim_ids: BTreeSet<&str> = config
        .evidence
        .claims
        .iter()
        .map(|claim| claim.id.as_str())
        .collect();
    let mut diagnostics = Vec::new();
    for (profile_id, profile) in &config.evidence.credential_profiles {
        for claim_id in &profile.allowed_claims {
            if !claim_ids.contains(claim_id.as_str()) {
                diagnostics.push(Diagnostic::fail(
                    format!("{profile_id} allows unknown claim {claim_id}"),
                    "remove the claim id or add the claim definition",
                ));
                continue;
            }
            let claim = config
                .evidence
                .claims
                .iter()
                .find(|claim| claim.id == *claim_id)
                .expect("claim was checked above");
            if !claim
                .credential_profiles
                .iter()
                .any(|configured| configured == profile_id)
            {
                diagnostics.push(Diagnostic::fail(
                    format!("{claim_id} does not opt into credential profile {profile_id}"),
                    "add the profile id to the claim credential_profiles list",
                ));
            } else {
                diagnostics.push(Diagnostic::ok(format!(
                    "{profile_id} can issue claim {claim_id}"
                )));
            }
        }
    }
    if issue_demo_vc {
        diagnostics.push(Diagnostic::ok(
            "local VC wiring checked; demo credential issuance requires an HTTP request with a holder proof when configured",
        ));
    }
    diagnostics
}

fn dci_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    subject_id_type: Option<&str>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (connection_id, connection) in &config.evidence.source_connections {
        let Some(binding) = first_dci_binding_for_connection(config, connection_id) else {
            continue;
        };
        if connection.dci.search_path.trim().is_empty() {
            continue;
        }
        let dci = match connection.effective_dci() {
            Ok(dci) => dci,
            Err(err) => {
                diagnostics.push(Diagnostic::fail(
                    format!("{connection_id} DCI expansion failed: {err}"),
                    "fix the DCI block",
                ));
                continue;
            }
        };
        if dci.records_path.trim().is_empty() {
            diagnostics.push(Diagnostic::fail(
                format!("{connection_id} DCI records_path is empty"),
                "set records_path to the JSON pointer containing registry records",
            ));
        } else {
            let lookup_field = subject_id_type
                .or(Some(binding.lookup.field.as_str()))
                .unwrap_or("configured lookup field");
            diagnostics.push(Diagnostic::ok(format!(
                "{connection_id} DCI request can be constructed for lookup field {lookup_field}"
            )));
        }
    }
    diagnostics
}

async fn live_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    target_id: Option<&str>,
    target_id_type: Option<&str>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (connection_id, connection) in &config.evidence.source_connections {
        if let Some(SourceAuthConfig::Oauth2ClientCredentials(auth)) = &connection.source_auth {
            match fetch_oauth_token_for_doctor(connection_id, connection, auth).await {
                Ok(token) => {
                    diagnostics.push(Diagnostic::ok(format!(
                        "{connection_id} OAuth token fetched without printing the token"
                    )));
                    if let Some(target_id) = target_id {
                        diagnostics.push(
                            dci_record_probe(
                                config,
                                connection_id,
                                connection,
                                &token,
                                target_id,
                                target_id_type,
                            )
                            .await,
                        );
                    } else {
                        diagnostics.push(Diagnostic::ok(
                            "record-level live probe skipped because --target-id was not supplied",
                        ));
                    }
                }
                Err(diagnostic) => diagnostics.push(diagnostic),
            }
        }
    }
    if diagnostics.is_empty() {
        diagnostics.push(Diagnostic::ok(
            "live source probe skipped because no OAuth source_auth is configured",
        ));
    }
    diagnostics
}

async fn fetch_oauth_token_for_doctor(
    connection_id: &str,
    connection: &registry_notary_core::SourceConnectionConfig,
    auth: &Oauth2ClientCredentialsSourceAuthConfig,
) -> Result<String, Diagnostic> {
    let token_url = match reqwest::Url::parse(&auth.token_url) {
        Ok(url) => url,
        Err(err) => {
            return Err(Diagnostic::fail(
                format!("{connection_id} OAuth token_url is invalid: {err}"),
                "fix source_auth.token_url",
            ));
        }
    };
    let validated_token_url = match cli_fetch_url_policy(connection)
        .validate_dns_pinned_for_immediate_fetch(&token_url)
    {
        Ok(validated) => validated,
        Err(err) => {
            return Err(Diagnostic::fail(
                format!("{connection_id} OAuth token_url is blocked by fetch policy: {err}"),
                "use HTTPS for production or explicitly enable the localhost/private-network development escape hatch",
            ));
        }
    };
    let client_id = match std::env::var(&auth.client_id_env) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            return Err(Diagnostic::fail(
                format!("{connection_id} OAuth client id is unavailable"),
                format!("set {}", auth.client_id_env),
            ));
        }
    };
    let client_secret = match std::env::var(&auth.client_secret_env) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            return Err(Diagnostic::fail(
                format!("{connection_id} OAuth client secret is unavailable"),
                format!("set {}", auth.client_secret_env),
            ));
        }
    };
    let mut request = validated_token_url
        .immediate_post_with_timeout(Duration::from_secs(10))
        .map_err(|err| {
            Diagnostic::fail(
                format!("{connection_id} OAuth token request could not be built: {err}"),
                "check token_url reachability and local network/TLS settings",
            )
        })?;
    if auth.request_format == "json" {
        let mut body = json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        });
        if !auth.scope.trim().is_empty() {
            body["scope"] = Value::String(auth.scope.clone());
        }
        request = request.json(&body);
    } else {
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];
        if !auth.scope.trim().is_empty() {
            form.push(("scope", auth.scope.clone()));
        }
        request = request.form(&form);
    }
    let response = match request.send().await {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            return Err(Diagnostic::fail(
                format!(
                    "{connection_id} OAuth token endpoint returned {}",
                    response.status()
                ),
                "check client id, client secret, token URL, and request_format",
            ))
        }
        Err(err) => {
            return Err(Diagnostic::fail(
                format!("{connection_id} OAuth token fetch failed: {err}"),
                "check token_url reachability and local network/TLS settings",
            ))
        }
    };
    let body = response.json::<Value>().await.map_err(|err| {
        Diagnostic::fail(
            format!("{connection_id} OAuth token response was not JSON: {err}"),
            "check the token endpoint response shape",
        )
    })?;
    body.get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            Diagnostic::fail(
                format!("{connection_id} OAuth token response had no access_token"),
                "check the token endpoint response shape",
            )
        })
}

async fn dci_record_probe(
    config: &StandaloneRegistryNotaryConfig,
    connection_id: &str,
    connection: &registry_notary_core::SourceConnectionConfig,
    token: &str,
    subject_id: &str,
    subject_id_type: Option<&str>,
) -> Diagnostic {
    let Some(binding) = first_dci_binding_for_connection(config, connection_id) else {
        return Diagnostic::ok(format!(
            "{connection_id} record-level live probe skipped because no DCI binding uses it"
        ));
    };
    let dci = match connection.effective_dci() {
        Ok(dci) => dci,
        Err(err) => {
            return Diagnostic::fail(
                format!("{connection_id} DCI expansion failed during live probe: {err}"),
                "fix the DCI block",
            );
        }
    };
    let url = match source_url_for_cli(&connection.base_url, &dci.search_path) {
        Ok(url) => url,
        Err(err) => {
            return Diagnostic::fail(
                format!("{connection_id} DCI search URL is invalid: {err}"),
                "fix source base_url and dci.search_path",
            );
        }
    };
    let validated_url = match cli_fetch_url_policy(connection)
        .validate_dns_pinned_for_immediate_fetch(&url)
    {
        Ok(validated) => validated,
        Err(err) => {
            return Diagnostic::fail(
                format!("{connection_id} DCI search URL is blocked by fetch policy: {err}"),
                "use HTTPS for production or explicitly enable the localhost/private-network development escape hatch",
            );
        }
    };
    let body = match dci_probe_body(&dci, binding, subject_id, subject_id_type) {
        Ok(body) => body,
        Err(err) => {
            return Diagnostic::fail(
                format!("{connection_id} DCI probe body could not be built: {err}"),
                "check dci.query_type and binding lookup fields",
            );
        }
    };
    let request = match validated_url.immediate_post_with_timeout(Duration::from_secs(10)) {
        Ok(request) => request,
        Err(err) => {
            return Diagnostic::fail(
                format!("{connection_id} DCI search request could not be built: {err}"),
                "check source base_url reachability and local network/TLS settings",
            );
        }
    };
    let response = match request
        .bearer_auth(token)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .header(
            "data-purpose",
            "https://registry-notary.local/purpose/doctor",
        )
        .json(&body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Diagnostic::fail(
                format!("{connection_id} DCI live probe failed: {err}"),
                "check DCI endpoint reachability",
            );
        }
    };
    let status = response.status();
    if !status.is_success() {
        return Diagnostic::fail(
            format!("{connection_id} DCI live probe returned {status}"),
            "check the sample subject, DCI auth, and source DCI request settings",
        );
    }
    let body = match response.json::<Value>().await {
        Ok(body) => body,
        Err(err) => {
            return Diagnostic::fail(
                format!("{connection_id} DCI live probe response was not JSON: {err}"),
                "check the DCI response shape",
            );
        }
    };
    match body.pointer(&dci.records_path).and_then(Value::as_array) {
        Some(records) if !records.is_empty() => Diagnostic::ok(format!(
            "{connection_id} DCI records_path resolved for sample subject (subject redacted)"
        )),
        Some(_) => Diagnostic::fail(
            format!("{connection_id} DCI records_path resolved but contained no records"),
            "check the redacted sample subject id exists in the upstream demo or test environment",
        ),
        None => Diagnostic::fail(
            format!("{connection_id} DCI records_path did not resolve in live response"),
            "check dci.records_path against the DCI response shape",
        ),
    }
}

fn first_dci_binding_for_connection<'a>(
    config: &'a StandaloneRegistryNotaryConfig,
    connection_id: &str,
) -> Option<&'a registry_notary_core::SourceBindingConfig> {
    config
        .evidence
        .claims
        .iter()
        .flat_map(|claim| claim.source_bindings.values())
        .find(|binding| {
            binding.connection.as_deref() == Some(connection_id)
                && binding.connector == registry_notary_core::SourceConnectorKind::Dci
        })
}

fn source_url_for_cli(base_url: &str, path: &str) -> Result<reqwest::Url, String> {
    if reqwest::Url::parse(path).is_ok() {
        return Err("dci.search_path must be relative".to_string());
    }
    let base = reqwest::Url::parse(base_url).map_err(|err| err.to_string())?;
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(base);
    }
    let segments = trimmed
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    httputil_url::append_path_segments(&base, &segments).map_err(|err| err.to_string())
}

fn dci_probe_body(
    dci: &registry_notary_core::DciSourceConnectionConfig,
    binding: &registry_notary_core::SourceBindingConfig,
    subject_id: &str,
    subject_id_type: Option<&str>,
) -> Result<Value, String> {
    let message_id = Ulid::new().to_string();
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| err.to_string())?;
    let lookup_field = if dci.query_type == "idtype-value" {
        subject_id_type.unwrap_or(binding.lookup.field.as_str())
    } else {
        binding.lookup.field.as_str()
    };
    let lookup_value = Value::String(subject_id.to_string());
    let query = match dci.query_type.as_str() {
        "idtype-value" => json!({
            "type": lookup_field,
            "value": lookup_value,
        }),
        "expression" => json!({
            lookup_field: {
                binding.lookup.op.clone(): lookup_value,
            },
        }),
        "predicate" => json!([{
            "expression1": {
                "attribute_name": lookup_field,
                "operator": binding.lookup.op,
                "attribute_value": lookup_value,
            },
        }]),
        _ => return Err("unsupported dci.query_type".to_string()),
    };
    let mut search_criteria = serde_json::Map::from_iter([
        (
            "query_type".to_string(),
            Value::String(dci.query_type.clone()),
        ),
        ("query".to_string(), query),
        (
            "pagination".to_string(),
            json!({ "page_size": dci.max_results.max(2), "page_number": 1 }),
        ),
    ]);
    if let Some(registry_type) = &dci.registry_type {
        search_criteria.insert("reg_type".to_string(), Value::String(registry_type.clone()));
    }
    if let Some(registry_event_type) = &dci.registry_event_type {
        search_criteria.insert(
            "reg_event_type".to_string(),
            Value::String(registry_event_type.clone()),
        );
    }
    if let Some(record_type) = &dci.record_type {
        search_criteria.insert(
            "reg_record_type".to_string(),
            Value::String(record_type.clone()),
        );
    }
    Ok(json!({
        "header": {
            "message_id": message_id,
            "message_ts": timestamp,
            "action": "search",
            "sender_id": dci.sender_id,
            "total_count": 1,
            "is_msg_encrypted": false,
        },
        "message": {
            "transaction_id": message_id,
            "search_request": [{
                "reference_id": message_id,
                "timestamp": timestamp,
                "search_criteria": Value::Object(search_criteria),
            }],
        },
    }))
}

fn explain_config(
    config_path: &Path,
    env_report: &EnvFileReport,
    bind_override: Option<SocketAddr>,
    format: ExplainConfigOutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(config_path)?;
    let mut config = parse_expanded_config(&raw)?;
    apply_bind_override(&mut config, bind_override);
    match format {
        ExplainConfigOutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&config_explanation_json(
                    config_path,
                    &raw,
                    &config,
                    env_report,
                ))?
            );
        }
        ExplainConfigOutputFormat::Text => {
            println!(
                "{}",
                serde_json::to_string_pretty(&redacted_config(&config))?
            );
            println!();
            println!("Required env vars:");
            for env in required_env_vars(&config) {
                let status = if std::env::var_os(&env).is_some() {
                    "present"
                } else if env_report.contains(&env) {
                    "from env-file"
                } else {
                    "missing"
                };
                println!("- {env}: {status}");
            }
            println!();
            println!("Claim source bindings:");
            for claim in &config.evidence.claims {
                for (binding_id, binding) in &claim.source_bindings {
                    println!(
                        "- {}.{} uses connection {} via {:?}",
                        claim.id,
                        binding_id,
                        binding.connection.as_deref().unwrap_or("(default)"),
                        binding.connector
                    );
                }
            }
        }
    }
    Ok(())
}

fn config_explanation_json(
    config_path: &Path,
    raw_config: &str,
    config: &StandaloneRegistryNotaryConfig,
    env_report: &EnvFileReport,
) -> Value {
    json!({
        "schema_version": "registry.config.explanation.v1",
        "product": "registry-notary",
        "config_schema_version": NOTARY_CONFIG_SCHEMA_VERSION,
        "source": {
            "kind": "local_file",
            "path": path_for_json(config_path),
        },
        "required_env": required_env_report(required_env_vars(config), env_report),
        "defaults_applied": [],
        "optional_sections_absent": optional_config_sections_absent(config),
        "live_apply": notary_live_apply_classes(),
        "context_constraints": notary_context_constraints_report(config),
        "resolved_config": redacted_config(config),
        "hashes": {
            "internal_config_hash": sha256_hash(raw_config),
        },
        "generated_at": now_rfc3339(),
    })
}

fn optional_config_sections_absent(config: &StandaloneRegistryNotaryConfig) -> Vec<Value> {
    let mut sections = Vec::new();
    if config.evidence.source_connections.is_empty() {
        sections.push(json!({
            "path": "/evidence/source_connections",
            "reason": "no external source connections configured",
        }));
    }
    if !config.credential_status.enabled {
        sections.push(json!({
            "path": "/credential_status",
            "reason": "credential status is disabled",
        }));
    }
    sections
}

fn notary_context_constraints_report(config: &StandaloneRegistryNotaryConfig) -> Vec<Value> {
    let mut entries = Vec::new();
    for (claim_index, claim) in config.evidence.claims.iter().enumerate() {
        for (binding_id, binding) in &claim.source_bindings {
            let matching = &binding.matching;
            if !notary_matching_has_context_constraints(matching) {
                continue;
            }
            let legal_basis_source = notary_trusted_value_source(
                config,
                "legal_basis",
                notary_legal_basis_configured(matching),
            );
            let consent_source =
                notary_trusted_value_source(config, "consent", notary_consent_configured(matching));
            let jurisdiction_source = notary_trusted_value_source(
                config,
                "jurisdiction",
                !matching.permitted_jurisdictions.is_empty(),
            );
            let assurance_source = notary_trusted_value_source(
                config,
                "assurance",
                !matching.allowed_assurance.is_empty() || matching.minimum_assurance.is_some(),
            );
            let (observation_source, observation_proven) =
                notary_source_observation_report(config, binding);

            entries.push(json!({
                "container_path": format!(
                    "/evidence/claims/{claim_index}/source_bindings/{}/matching",
                    json_pointer_segment(binding_id)
                ),
                "product": "registry-notary",
                "platform_contract": PLATFORM_CONTEXT_CONSTRAINTS_CONTRACT_V1,
                "hash_material_contract": PLATFORM_CONTEXT_CONSTRAINTS_HASH_MATERIAL_CONTRACT_V1,
                "legal_basis": {
                    "required": matching.require_legal_basis,
                    "approved_value_check": !matching.allowed_legal_basis_refs.is_empty(),
                    "allowed_ref_count": matching.allowed_legal_basis_refs.len(),
                    "trusted_value_source": legal_basis_source,
                },
                "consent": {
                    "required": matching.require_consent,
                    "approved_value_check": !matching.allowed_consent_refs.is_empty(),
                    "allowed_ref_count": matching.allowed_consent_refs.len(),
                    "trusted_value_source": consent_source,
                },
                "jurisdiction": {
                    "permitted_count": matching.permitted_jurisdictions.len(),
                    "trusted_value_source": jurisdiction_source,
                },
                "assurance": {
                    "allowed_count": matching.allowed_assurance.len(),
                    "minimum": matching.minimum_assurance.as_deref(),
                    "trusted_value_source": assurance_source,
                    "authn_derived": false,
                },
                "source_freshness": {
                    "max_age_seconds": matching.max_source_age_seconds,
                    "observation_field": matching.source_observed_at_field.as_deref(),
                    "observation_timestamp_source": observation_source,
                    "observation_contract_proven": observation_proven,
                },
                "product_owned_adjacent_controls": notary_adjacent_matching_controls(binding),
            }));
        }
    }
    entries
}

fn notary_matching_has_context_constraints(
    matching: &registry_notary_core::SourceMatchingConfig,
) -> bool {
    matching.has_context_constraints()
}

fn notary_legal_basis_configured(matching: &registry_notary_core::SourceMatchingConfig) -> bool {
    matching.require_legal_basis || !matching.allowed_legal_basis_refs.is_empty()
}

fn notary_consent_configured(matching: &registry_notary_core::SourceMatchingConfig) -> bool {
    matching.require_consent || !matching.allowed_consent_refs.is_empty()
}

fn notary_trusted_value_source(
    config: &StandaloneRegistryNotaryConfig,
    field: &str,
    configured: bool,
) -> &'static str {
    if !configured {
        return TrustedValueSource::NotConfigured.as_str();
    }
    if notary_static_authorization_details_has(config, field) {
        return TrustedValueSource::StaticCredentialAuthorizationDetails.as_str();
    }
    if config.auth.mode == EvidenceAuthMode::Oidc {
        return TrustedValueSource::OidcAuthorizationDetails.as_str();
    }
    TrustedValueSource::Unknown.as_str()
}

fn notary_static_authorization_details_has(
    config: &StandaloneRegistryNotaryConfig,
    field: &str,
) -> bool {
    config
        .auth
        .api_keys
        .iter()
        .chain(config.auth.bearer_tokens.iter())
        .filter_map(|credential| credential.authorization_details.as_ref())
        .any(|details| match field {
            "legal_basis" => details.legal_basis_ref.as_deref().is_some_and(non_empty),
            "consent" => details.consent_ref.as_deref().is_some_and(non_empty),
            "jurisdiction" => details.jurisdiction.as_deref().is_some_and(non_empty),
            "assurance" => details.assurance_level.as_deref().is_some_and(non_empty),
            _ => false,
        })
}

fn notary_source_observation_report(
    config: &StandaloneRegistryNotaryConfig,
    binding: &registry_notary_core::SourceBindingConfig,
) -> (&'static str, bool) {
    if binding.matching.max_source_age_seconds.is_none() {
        return (TrustedValueSource::NotConfigured.as_str(), false);
    }
    let Some(field) = binding.matching.source_observed_at_field.as_deref() else {
        return (TrustedValueSource::Unknown.as_str(), false);
    };
    if binding.connector != SourceConnectorKind::Dci {
        return (TrustedValueSource::Unknown.as_str(), false);
    }
    let Some(connection_id) = binding.connection.as_deref() else {
        return (TrustedValueSource::Unknown.as_str(), false);
    };
    let Some(connection) = config.evidence.source_connections.get(connection_id) else {
        return (TrustedValueSource::Unknown.as_str(), false);
    };
    if connection
        .dci
        .field_paths
        .get(field)
        .is_some_and(|path| path.starts_with("$response:"))
    {
        return (
            TrustedValueSource::SourceObservationTimestamp.as_str(),
            true,
        );
    }
    (TrustedValueSource::Unknown.as_str(), false)
}

fn notary_adjacent_matching_controls(
    binding: &registry_notary_core::SourceBindingConfig,
) -> Vec<&'static str> {
    let matching = &binding.matching;
    let mut controls = vec!["source_lookup"];
    if !matching.sufficient_target_inputs.is_empty() || !matching.allowed_target_inputs.is_empty() {
        controls.push("target_input_minimization");
    }
    if matching.collapse_matching_errors {
        controls.push("matching_error_collapse");
    }
    if matching.confidence.is_some() {
        controls.push("confidence_label");
    }
    if !matching.redaction_fields.is_empty() {
        controls.push("redaction_fields");
    }
    controls
}

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn notary_live_apply_classes() -> Vec<Value> {
    vec![
        json!({
            "path": "/evidence/source_connections",
            "class": LiveApplyClass::RestartRequired.as_str(),
        }),
        json!({
            "path": "/evidence/signing_keys",
            "class": LiveApplyClass::RestartRequired.as_str(),
        }),
        json!({
            "path": "/server",
            "class": LiveApplyClass::RestartRequired.as_str(),
        }),
        json!({
            "path": "/config_trust",
            "class": LiveApplyClass::UnsupportedLiveApply.as_str(),
        }),
    ]
}

fn apply_bind_override(config: &mut StandaloneRegistryNotaryConfig, bind: Option<SocketAddr>) {
    if let Some(bind) = bind {
        config.server.bind = bind;
    }
}

fn required_env_vars(config: &StandaloneRegistryNotaryConfig) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    for credential in config
        .auth
        .api_keys
        .iter()
        .chain(config.auth.bearer_tokens.iter())
    {
        if let Some(env) = credential.fingerprint.name.clone() {
            vars.insert(env);
        }
    }
    if let Some(env) = &config.audit.hash_secret_env {
        vars.insert(env.clone());
    }
    if config.replay.storage == "redis" {
        vars.insert(config.replay.redis.url_env.clone());
    }
    if config.credential_status.enabled && config.credential_status.storage == "redis" {
        vars.insert(config.credential_status.redis.url_env.clone());
    }
    if config.federation.enabled {
        vars.insert(config.federation.pairwise_subject_hash.secret_env.clone());
    }
    for connection in config.evidence.source_connections.values() {
        if !connection.token_env.trim().is_empty() {
            vars.insert(connection.token_env.clone());
        }
        if let Some(SourceAuthConfig::Oauth2ClientCredentials(auth)) = &connection.source_auth {
            vars.insert(auth.client_id_env.clone());
            vars.insert(auth.client_secret_env.clone());
        }
    }
    for key in config.evidence.signing_keys.values() {
        if !key.private_jwk_env.trim().is_empty() {
            vars.insert(key.private_jwk_env.clone());
        }
        if !key.public_jwk_env.trim().is_empty() {
            vars.insert(key.public_jwk_env.clone());
        }
        if !key.pin_env.trim().is_empty() {
            vars.insert(key.pin_env.clone());
        }
        if !key.password_env.trim().is_empty() {
            vars.insert(key.password_env.clone());
        }
    }
    vars
}

fn redacted_config(config: &StandaloneRegistryNotaryConfig) -> Value {
    let mut value = serde_json::to_value(config).expect("config serializes");
    redact_value(&mut value);
    value
}

fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if ["secret", "token", "jwk", "pin", "password"]
                    .iter()
                    .any(|term| lower.contains(term))
                    || (lower.contains("key") && lower != "signing_keys" && lower != "api_keys")
                    || lower == "credential"
                    || lower.ends_with("_credential")
                    || lower == "credential_env"
                {
                    *value = Value::String("[redacted]".to_string());
                } else {
                    redact_value(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_value(value);
            }
        }
        _ => {}
    }
}

#[derive(Debug)]
struct InitDciOptions {
    base_url: String,
    token_url: String,
    lookup_field: String,
    claim_id: String,
    claim_title: String,
    demo_issuer: bool,
    with_env_file: bool,
    force: bool,
    print_secrets: bool,
}

fn init_dci(output: &Path, options: InitDciOptions) -> Result<(), Box<dyn std::error::Error>> {
    validate_init_dci_options(&options)?;
    fs::create_dir_all(output)?;
    let api_key = random_secret("rn_api");
    let api_hash = sha256_hash(&api_key);
    let audit_secret = random_secret("rn_audit");
    let issuer_jwk = if options.demo_issuer {
        Some(demo_issuer_jwk("did:web:localhost#registry-notary-demo")?)
    } else {
        None
    };
    write_generated_file(
        &output.join("dci-notary.yaml"),
        &dci_config_yaml(&options),
        options.force,
        false,
    )?;
    write_generated_file(
        &output.join(".env.local.example"),
        &dci_env_example(options.demo_issuer),
        options.force,
        false,
    )?;
    if options.with_env_file {
        write_generated_file(
            &output.join(".env.local"),
            &dci_env_local(&api_key, &api_hash, &audit_secret, issuer_jwk.as_deref()),
            options.force,
            true,
        )?;
    }
    write_generated_file(
        &output.join("README.dci.md"),
        dci_readme(),
        options.force,
        false,
    )?;
    println!("Generated DCI starter files in {}", output.display());
    if options.print_secrets {
        println!("REGISTRY_NOTARY_LOCAL_API_KEY={api_key}");
        println!("REGISTRY_NOTARY_API_KEY_HASH={api_hash}");
        println!("REGISTRY_NOTARY_AUDIT_HASH_SECRET={audit_secret}");
        if let Some(jwk) = issuer_jwk {
            println!("REGISTRY_NOTARY_ISSUER_JWK={jwk}");
        }
    } else if options.with_env_file {
        println!("Local secrets were written to .env.local and were not printed.");
    } else {
        println!(
            "Run `registry-notary hash-api-key --print-secret` to create local API credentials."
        );
    }
    Ok(())
}

fn validate_init_dci_options(options: &InitDciOptions) -> Result<(), Box<dyn std::error::Error>> {
    for (name, value) in [
        ("base_url", options.base_url.as_str()),
        ("token_url", options.token_url.as_str()),
        ("lookup_field", options.lookup_field.as_str()),
        ("claim_id", options.claim_id.as_str()),
        ("claim_title", options.claim_title.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{name} must not be empty").into());
        }
        if value.contains(['\n', '\r']) {
            return Err(format!("{name} must not contain line breaks").into());
        }
    }
    reqwest::Url::parse(&options.base_url)
        .map_err(|err| format!("base_url must be an absolute URL: {err}"))?;
    reqwest::Url::parse(&options.token_url)
        .map_err(|err| format!("token_url must be an absolute URL: {err}"))?;
    Ok(())
}

fn write_generated_file(
    path: &Path,
    contents: &str,
    force: bool,
    secret: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() && !force {
        return Err(format!("{} exists; pass --force to overwrite", path.display()).into());
    }
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    if secret {
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents.as_bytes())?;
    Ok(())
}

fn dci_config_yaml(options: &InitDciOptions) -> String {
    let claim_id = yaml_string(&options.claim_id);
    let claim_title = yaml_string(&options.claim_title);
    let base_url = yaml_string(&options.base_url);
    let token_url = yaml_string(&options.token_url);
    let lookup_field = yaml_string(&options.lookup_field);
    let credential_profile = if options.demo_issuer {
        format!(
            r#"
  signing_keys:
    registry-notary-demo:
      provider: local_jwk_env
      private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
      alg: EdDSA
      kid: did:web:localhost#registry-notary-demo
      status: active
  credential_profiles:
    dci_record_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:localhost
      signing_key: registry-notary-demo
      vct: https://registry-notary.local/credentials/dci-record
      allowed_claims: [{claim_id}]
      holder_binding:
        mode: none
"#
        )
    } else {
        String::new()
    };
    let claim_profiles = if options.demo_issuer {
        "      credential_profiles: [dci_record_sd_jwt]\n"
    } else {
        ""
    };
    format!(
        r#"server:
  bind: 127.0.0.1:4255
auth:
  mode: api_key
  api_keys:
    - id: local-demo
      fingerprint:
        provider: env
        name: REGISTRY_NOTARY_API_KEY_HASH
      scopes: [dci:evidence_verification]
audit:
  sink: file
  path: ./dci-notary.audit.jsonl
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: dci-notary-demo
  source_connections:
    dci_registry:
      base_url: {base_url}
      source_auth:
        type: oauth2_client_credentials
        token_url: {token_url}
        client_id_env: DCI_CLIENT_ID
        client_secret_env: DCI_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
{credential_profile}  claims:
    - id: {claim_id}
      title: {claim_title}
      version: 2026-05
      subject_type: person
      value:
        type: boolean
{claim_profiles}      source_bindings:
        record:
          connector: dci
          connection: dci_registry
          required_scope: dci:evidence_verification
          dataset: registry_records
          entity: record
          lookup:
            input: target.id
            field: {lookup_field}
            op: eq
            cardinality: one
          fields:
            id:
              field: id
              type: string
              required: false
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
        - application/dc+sd-jwt
"#
    )
}

fn yaml_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn cli_fetch_url_policy(
    connection: &registry_notary_core::SourceConnectionConfig,
) -> FetchUrlPolicy {
    if connection.allow_insecure_private_network {
        FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: true,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        }
    } else if connection.allow_insecure_localhost {
        FetchUrlPolicy::dev()
    } else {
        FetchUrlPolicy::strict()
    }
}

fn dci_env_example(demo_issuer: bool) -> String {
    let issuer = if demo_issuer {
        "REGISTRY_NOTARY_ISSUER_JWK=<generated by registry-notary demo-issuer-key>\n"
    } else {
        ""
    };
    format!(
        r#"# Copy to .env.local or run init with --with-env-file.
REGISTRY_NOTARY_API_KEY=<random local API key>
REGISTRY_NOTARY_API_KEY_HASH=sha256:<64 hex>
REGISTRY_NOTARY_AUDIT_HASH_SECRET=<random local audit secret>
DCI_CLIENT_ID=<DCI OAuth client id>
DCI_CLIENT_SECRET=<DCI OAuth client secret>
{issuer}"#
    )
}

fn dci_env_local(
    api_key: &str,
    api_hash: &str,
    audit_secret: &str,
    issuer_jwk: Option<&str>,
) -> String {
    let issuer = issuer_jwk
        .map(|jwk| format!("REGISTRY_NOTARY_ISSUER_JWK='{jwk}'\n"))
        .unwrap_or_default();
    format!(
        r#"REGISTRY_NOTARY_API_KEY={api_key}
REGISTRY_NOTARY_API_KEY_HASH={api_hash}
REGISTRY_NOTARY_AUDIT_HASH_SECRET={audit_secret}
DCI_CLIENT_ID=replace-me
DCI_CLIENT_SECRET=replace-me
{issuer}"#
    )
}

fn dci_readme() -> &'static str {
    r#"# DCI Registry Notary Starter

1. Fill `DCI_CLIENT_ID` and `DCI_CLIENT_SECRET` in `.env.local`.
2. Edit `dci-notary.yaml` for the DCI server's base URL, token URL, query type,
   registry filters, lookup field, and records path.
3. Run `registry-notary doctor --config dci-notary.yaml --env-file .env.local`.
4. Run `registry-notary doctor --config dci-notary.yaml --env-file .env.local --live`.
5. Start with `registry-notary --config dci-notary.yaml --env-file .env.local`.

The generated config uses explicit DCI config fields and generic
`source_auth.type = oauth2_client_credentials`. It does not depend on any
built-in registry-specific code path.
"#
}

fn hash_api_key(
    stdin: bool,
    hash_only: bool,
    print_secret: bool,
    api_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let api_key = if stdin {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input.trim_end_matches(['\r', '\n']).to_string()
    } else {
        api_key.unwrap_or_else(|| random_secret("rn_api"))
    };
    if api_key.trim().is_empty() {
        return Err("api key must not be empty".into());
    }
    let hash = sha256_hash(&api_key);
    if hash_only {
        println!("{hash}");
    } else if print_secret {
        println!("api_key={api_key}");
        println!("hash={hash}");
    } else if stdin {
        println!("{hash}");
    } else {
        println!("hash={hash}");
        println!("plaintext key generated; rerun with --print-secret to display it");
    }
    Ok(())
}

fn random_secret(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness is available");
    format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn sha256_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut hash = String::with_capacity("sha256:".len() + digest.len() * 2);
    hash.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hash, "{byte:02x}").expect("writing to string cannot fail");
    }
    hash
}

fn demo_issuer_jwk(kid: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": kid,
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
    });
    let serialized = serde_json::to_string(&jwk)?;
    PrivateJwk::parse(&serialized)?;
    Ok(serialized)
}

fn lightweight_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Registry Notary standalone config",
        "type": "object",
        "required": ["auth", "evidence"],
        "properties": {
            "server": { "type": "object" },
            "auth": { "type": "object" },
            "audit": { "type": "object" },
            "replay": { "type": "object" },
            "credential_status": { "type": "object" },
            "self_attestation": { "type": "object" },
            "oid4vci": { "type": "object" },
            "evidence": { "type": "object" },
            "federation": { "type": "object" }
        },
        "additionalProperties": false
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use axum_test::TestServer;
    use registry_platform_config::{
        sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
        ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
    };
    use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const CONFIG_BUNDLE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

    #[derive(Clone, Default)]
    struct DoctorLiveState {
        token_called: Arc<AtomicBool>,
        dci_called: Arc<AtomicBool>,
    }

    struct SignedBundleFixture {
        bundle_dir: PathBuf,
        anchor_path: PathBuf,
        state_path: PathBuf,
        config_hash: String,
    }

    fn write_signed_notary_bundle(tmp: &tempfile::TempDir) -> SignedBundleFixture {
        let bundle_dir = tmp.path().join("bundle");
        let config_dir = bundle_dir.join("config");
        std::fs::create_dir_all(&config_dir).expect("bundle config dir");
        let config = notary_bundle_runtime_config();
        std::fs::write(config_dir.join("notary.yaml"), config.as_bytes()).expect("config writes");
        let config_hash = sha256_uri(config.as_bytes());
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
        let public = private.public();
        let kid = public.jkt().expect("thumbprint");
        let manifest = ConfigBundleManifest {
            schema: "registry.platform.config_bundle.v1".to_string(),
            product: "registry-notary".to_string(),
            environment: "development".to_string(),
            stream_id: "notary-loader-test".to_string(),
            instance_id: None,
            bundle_id: "notary-loader-bundle".to_string(),
            sequence: 1,
            previous_config_hash: None,
            config_hash: config_hash.clone(),
            files: vec![ConfigBundleFile {
                path: "config/notary.yaml".to_string(),
                sha256: config_hash.clone(),
            }],
            created_at: "2026-07-07T10:00:00Z".to_string(),
        };
        write_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);
        let anchor = ConfigTrustAnchor {
            schema: "registry.platform.config_trust_anchor.v1".to_string(),
            product: "registry-notary".to_string(),
            environment: "development".to_string(),
            stream_id: "notary-loader-test".to_string(),
            instance_id: "notary-loader".to_string(),
            signers: vec![ConfigTrustAnchorSigner {
                kid,
                jwk: public,
                enabled: true,
            }],
        };
        let anchor_path = tmp.path().join("trust_anchor.json");
        std::fs::write(
            &anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
        )
        .expect("anchor writes");
        SignedBundleFixture {
            bundle_dir,
            anchor_path,
            state_path: tmp.path().join("antirollback.json"),
            config_hash,
        }
    }

    fn write_manifest_and_signature(
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

    fn notary_bundle_runtime_config() -> String {
        r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:4255
  admin_listener:
    mode: dedicated
    bind: 127.0.0.1:4256
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_NOTARY_LOADER_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
  hash_secret_env: TEST_NOTARY_LOADER_AUDIT_HASH_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_NOTARY_LOADER_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
"#
        .to_string()
    }

    fn notary_bootstrap_config(fixture: &SignedBundleFixture) -> String {
        format!(
            r#"{}
config_trust:
  trust_anchor_path: {}
  bundle_path: {}
  antirollback_state_path: {}
"#,
            notary_bundle_runtime_config(),
            fixture.anchor_path.display(),
            fixture.bundle_dir.display(),
            fixture.state_path.display()
        )
    }

    async fn test_oauth_token(
        State(state): State<DoctorLiveState>,
        Json(body): Json<Value>,
    ) -> Response {
        state.token_called.store(true, Ordering::SeqCst);
        if body["grant_type"] != json!("client_credentials")
            || body["client_id"] != json!("doctor-client")
            || body["client_secret"] != json!("doctor-secret")
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        Json(json!({
            "access_token": "doctor-live-token",
            "expires_in": 300,
        }))
        .into_response()
    }

    async fn test_dci_search(
        State(state): State<DoctorLiveState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        state.dci_called.store(true, Ordering::SeqCst);
        if headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer doctor-live-token")
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok())
            != Some("https://registry-notary.local/purpose/doctor")
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let query = &body["message"]["search_request"][0]["search_criteria"]["query"];
        if query["type"] != json!("SUBJECT_ID") || query["value"] != json!("secret-subject-123") {
            return StatusCode::BAD_REQUEST.into_response();
        }
        Json(json!({
            "message": {
                "search_response": [{
                    "data": {
                        "reg_records": [{
                            "id": "record-1"
                        }]
                    }
                }]
            }
        }))
        .into_response()
    }

    #[test]
    fn env_file_parses_quotes_export_and_comments() {
        let parsed = parse_env_file(
            r#"
# comment
export API_HASH=sha256:abc # inline
CLIENT_ID="client value"
CLIENT_SECRET='secret value'
"#,
        )
        .expect("env file parses");
        assert_eq!(
            parsed,
            vec![
                ("API_HASH".to_string(), "sha256:abc".to_string()),
                ("CLIENT_ID".to_string(), "client value".to_string()),
                ("CLIENT_SECRET".to_string(), "secret value".to_string()),
            ]
        );
    }

    #[test]
    fn config_env_expansion_replaces_required_and_default_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("RN_CONFIG_EXPAND_REQUIRED", "https://upstream.example");
        std::env::remove_var("RN_CONFIG_EXPAND_DEFAULT");

        let expanded = expand_config_env_vars(
            "base_url: ${RN_CONFIG_EXPAND_REQUIRED:?missing upstream}\noptional: ${RN_CONFIG_EXPAND_DEFAULT:-fallback}\n",
        )
        .expect("config expands");

        assert!(expanded.contains("base_url: \"https://upstream.example\""));
        assert!(expanded.contains("optional: \"fallback\""));
        std::env::remove_var("RN_CONFIG_EXPAND_REQUIRED");
    }

    #[test]
    fn config_env_expansion_rejects_missing_required_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("RN_CONFIG_EXPAND_MISSING");

        let err = expand_config_env_vars("${RN_CONFIG_EXPAND_MISSING:?missing configured URL}")
            .expect_err("missing env var fails");

        assert!(err.to_string().contains("missing configured URL"));
    }

    #[test]
    fn config_env_expansion_rejects_invalid_variable_names() {
        let err =
            expand_config_env_vars("${NOT-A-VALID-NAME:-fallback}").expect_err("invalid var fails");

        assert!(err.to_string().contains("invalid env var name"));
    }

    #[test]
    fn signed_bundle_server_config_loads_with_pending_acceptance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fixture = write_signed_notary_bundle(&tmp);
        let config_path = tmp.path().join("bootstrap.yaml");
        std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");

        let loaded = load_server_config(&config_path, true).expect("signed bundle config loads");

        assert_eq!(loaded.config_source, ConfigSource::SignedBundleFile);
        let provenance = loaded.config_provenance.expect("provenance");
        assert_eq!(provenance.source, ConfigSource::SignedBundleFile);
        assert_eq!(provenance.internal_config_hash, fixture.config_hash);
        let acceptance = loaded
            .pending_bundle_acceptance
            .expect("pending acceptance");
        assert_eq!(acceptance.source, ConfigSource::SignedBundleFile);
        assert_eq!(
            acceptance.bundle_id.as_deref(),
            Some("notary-loader-bundle")
        );
        assert_eq!(acceptance.sequence, Some(1));
        assert_eq!(acceptance.config_hash, fixture.config_hash);
        assert!(matches!(
            acceptance.state_action,
            BundleStateAction::Initialize
        ));
    }

    #[test]
    fn boot_bundle_acceptance_audit_failure_aborts_before_antirollback_persist() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_path = tmp.path().join("antirollback.json");
        let acceptance = PendingBundleAcceptance {
            state_path: state_path.clone(),
            key: registry_platform_ops::AntiRollbackKey {
                product: "registry-notary".to_string(),
                instance_id: "notary-loader".to_string(),
                environment: "development".to_string(),
                stream_id: "notary-loader-test".to_string(),
            },
            source: ConfigSource::SignedBundleFile,
            bundle_id: Some("notary-loader-bundle".to_string()),
            bundle_manifest_hash: Some(
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_string(),
            ),
            sequence: Some(1),
            config_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
            previous_config_hash: None,
            previous_hash_matched: None,
            signer_kids: vec!["kid-1".to_string()],
            break_glass: false,
            state_action: BundleStateAction::Initialize,
            override_pin: None,
            override_path: None,
        };
        let audit_result: Result<(), Box<dyn std::error::Error>> =
            Err(Box::new(std::io::Error::other("boot audit write failed")));

        let result = persist_after_successful_boot_audit(&acceptance, audit_result);

        assert!(result.is_err());
        let err = registry_platform_ops::FileAntiRollbackStore::new(&state_path)
            .load(&acceptance.key)
            .expect_err("state remains absent");
        assert_eq!(
            err,
            registry_platform_ops::AntiRollbackStoreError::MissingState
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn boot_listener_bind_failure_aborts_before_antirollback_persist() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("TEST_NOTARY_LOADER_API_HASH", sha256_hash("api-token"));
        std::env::set_var(
            "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
            "registry-notary-loader-audit-secret-32-bytes",
        );
        std::env::set_var(
            "TEST_NOTARY_LOADER_ISSUER_JWK",
            demo_issuer_jwk("did:web:issuer.example#key-1").expect("issuer key generates"),
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let fixture = write_signed_notary_bundle(&tmp);
        let config_path = tmp.path().join("bootstrap.yaml");
        std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");
        let held_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        let held_addr = held_listener
            .local_addr()
            .expect("test listener exposes local addr");

        let error = run_server(&config_path, Some(held_addr), true)
            .await
            .expect_err("occupied listener rejects startup");

        assert!(
            error.to_string().contains("Address already in use"),
            "unexpected error: {error}"
        );
        let key = registry_platform_ops::AntiRollbackKey {
            product: "registry-notary".to_string(),
            instance_id: String::new(),
            environment: "development".to_string(),
            stream_id: "notary-loader-test".to_string(),
        };
        let err = registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path)
            .load(&key)
            .expect_err("state remains absent");
        assert_eq!(
            err,
            registry_platform_ops::AntiRollbackStoreError::MissingState
        );

        drop(held_listener);
        std::env::remove_var("TEST_NOTARY_LOADER_API_HASH");
        std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
        std::env::remove_var("TEST_NOTARY_LOADER_ISSUER_JWK");
    }

    #[test]
    fn default_log_filter_is_plain_info() {
        assert_eq!(default_log_filter(), "info");
        assert!(!default_log_filter().contains("debug"));
    }

    #[test]
    fn log_format_env_accepts_text_and_json() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("REGISTRY_NOTARY_LOG_FORMAT");
        assert_eq!(
            log_format_from_env().expect("default is text"),
            LogFormat::Text
        );

        std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "json");
        assert_eq!(
            log_format_from_env().expect("json is accepted"),
            LogFormat::Json
        );

        std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "text");
        assert_eq!(
            log_format_from_env().expect("text is accepted"),
            LogFormat::Text
        );

        std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "pretty");
        let err = log_format_from_env().expect_err("unknown format fails");
        assert!(err.contains("text"));
        assert!(err.contains("json"));

        std::env::remove_var("REGISTRY_NOTARY_LOG_FORMAT");
    }

    #[test]
    fn scalar_admin_listener_shape_names_accepted_modes() {
        let value = parse_config_value(
            r#"
server:
  admin_listener: shared_with_public
"#,
        )
        .expect("config shape parses");
        let err = validate_admin_listener_shape(&value)
            .expect_err("legacy scalar admin listener shape is rejected");

        let message = err.to_string();
        assert!(message.contains("server.admin_listener.mode"));
        assert!(message.contains("disabled"));
        assert!(message.contains("dedicated"));
        assert!(message.contains("shared_with_public"));
    }

    #[test]
    fn deprecated_config_fields_name_replacements_and_removed_cors_credentials() {
        for (raw, expected) in [
            (
                "auth:\n  oidc:\n    jwks_uri: https://id.example.gov/keys\n",
                "auth.oidc.jwks_url",
            ),
            (
                "auth:\n  oidc:\n    leeway_seconds: 60\n",
                "auth.oidc.leeway",
            ),
            (
                "auth:\n  oidc:\n    allowed_typ:\n      - JWT\n",
                "auth.oidc.allowed_token_types",
            ),
            (
                "server:\n  cors:\n    allow_credentials: true\n",
                "always disables credentialed CORS",
            ),
            ("audit:\n  max_size_bytes: 10485760\n", "audit.max_size_mb"),
        ] {
            let value = parse_config_value(raw).expect("deprecated-field fixture parses");
            let err = reject_deprecated_config_fields(&value, &deprecated_config_fields())
                .expect_err("deprecated field is rejected before deserialization");

            assert!(err.to_string().contains(expected), "unexpected: {err}");
        }
    }

    #[test]
    fn absent_admin_listener_block_requests_restore_key_warning() {
        let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(
            r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_ADMIN_WARNING_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_ADMIN_WARNING_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  credential_profiles:
    civil-status:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      signing_key: issuer
      vct: https://issuer.example/credentials/civil-status
"#,
        )
        .expect("config parses");

        assert!(admin_listener_default_warning_needed(&config, false));
        assert!(!admin_listener_default_warning_needed(&config, true));
    }

    #[test]
    fn env_file_ignores_quotes_inside_trailing_comments() {
        let parsed = parse_env_file(
            r#"
DOUBLE="client value" # comment with "quote"
SINGLE='secret value' # comment with 'quote'
ESCAPED="client \"quoted\" value" # comment with "quote"
"#,
        )
        .expect("env file parses");
        assert_eq!(
            parsed,
            vec![
                ("DOUBLE".to_string(), "client value".to_string()),
                ("SINGLE".to_string(), "secret value".to_string()),
                ("ESCAPED".to_string(), "client \"quoted\" value".to_string()),
            ]
        );
    }

    #[test]
    fn env_file_rejects_malformed_line_with_line_number() {
        let err = parse_env_file("GOOD=value\nnot valid\n").expect_err("line 2 fails");
        assert_eq!(err.line, 2);
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn env_file_does_not_overwrite_by_default() {
        std::env::set_var("RN_ENV_FILE_NO_OVERWRITE_TEST", "process");
        let report = apply_env_file("RN_ENV_FILE_NO_OVERWRITE_TEST=file\n", false)
            .expect("env file applies");
        assert_eq!(
            std::env::var("RN_ENV_FILE_NO_OVERWRITE_TEST").expect("env var exists"),
            "process"
        );
        assert!(report
            .skipped_existing
            .contains("RN_ENV_FILE_NO_OVERWRITE_TEST"));
        std::env::remove_var("RN_ENV_FILE_NO_OVERWRITE_TEST");
    }

    #[test]
    fn env_file_override_replaces_existing_process_value() {
        std::env::set_var("RN_ENV_FILE_OVERRIDE_TEST", "process");
        let report =
            apply_env_file("RN_ENV_FILE_OVERRIDE_TEST=file\n", true).expect("env file applies");
        assert_eq!(
            std::env::var("RN_ENV_FILE_OVERRIDE_TEST").expect("env var exists"),
            "file"
        );
        assert!(report.loaded.contains("RN_ENV_FILE_OVERRIDE_TEST"));
        std::env::remove_var("RN_ENV_FILE_OVERRIDE_TEST");
    }

    #[test]
    fn hash_api_key_uses_runtime_sha256_shape() {
        assert_eq!(
            sha256_hash("api-token"),
            "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51"
        );
    }

    #[test]
    fn healthcheck_cli_defaults_to_container_health_endpoint() {
        let args = Args::try_parse_from(["registry-notary", "healthcheck"]).expect("args parse");
        let Some(Command::Healthcheck { url, timeout_ms }) = args.command else {
            panic!("expected healthcheck command");
        };

        assert_eq!(url, "http://127.0.0.1:8080/healthz");
        assert_eq!(timeout_ms, 5000);
    }

    #[test]
    fn healthcheck_cli_accepts_url_and_timeout_overrides() {
        let args = Args::try_parse_from([
            "registry-notary",
            "healthcheck",
            "--url",
            "http://127.0.0.1:9000/ready",
            "--timeout-ms",
            "250",
        ])
        .expect("args parse");
        let Some(Command::Healthcheck { url, timeout_ms }) = args.command else {
            panic!("expected healthcheck command");
        };

        assert_eq!(url, "http://127.0.0.1:9000/ready");
        assert_eq!(timeout_ms, 250);
    }

    #[test]
    fn healthcheck_cli_rejects_zero_timeout() {
        let err = Args::try_parse_from(["registry-notary", "healthcheck", "--timeout-ms", "0"])
            .expect_err("zero timeout is rejected");

        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn doctor_cli_defaults_to_text_format() {
        let args = Args::try_parse_from(["registry-notary", "doctor"]).expect("args parse");
        let Some(Command::Doctor { format, .. }) = args.command else {
            panic!("expected doctor command");
        };

        assert_eq!(format, DoctorOutputFormat::Text);
    }

    #[test]
    fn doctor_cli_accepts_json_format() {
        let args = Args::try_parse_from(["registry-notary", "doctor", "--format", "json"])
            .expect("args parse");
        let Some(Command::Doctor { format, .. }) = args.command else {
            panic!("expected doctor command");
        };

        assert_eq!(format, DoctorOutputFormat::Json);
    }

    #[test]
    fn doctor_cli_accepts_profile_override() {
        let args = Args::try_parse_from(["registry-notary", "doctor", "--profile", "production"])
            .expect("args parse");
        let Some(Command::Doctor { profile, .. }) = args.command else {
            panic!("expected doctor command");
        };

        assert_eq!(profile.as_deref(), Some("production"));
    }

    #[test]
    fn doctor_cli_rejects_unknown_format() {
        let err = Args::try_parse_from(["registry-notary", "doctor", "--format", "pretty"])
            .expect_err("unknown doctor format is rejected");

        assert!(err.to_string().contains("text"));
        assert!(err.to_string().contains("json"));
    }

    #[test]
    fn build_info_cli_parses() {
        let args = Args::try_parse_from(["registry-notary", "build-info"]).expect("args parse");
        assert!(matches!(args.command, Some(Command::BuildInfo)));
    }

    #[test]
    fn config_verify_bundle_cli_accepts_bundle_flags() {
        let args = Args::try_parse_from([
            "registry-notary",
            "config",
            "verify-bundle",
            "--bundle-dir",
            "/etc/registry-notary/bundle",
            "--anchor-path",
            "/etc/registry-notary/trust_anchor.json",
            "--state-path",
            "/var/lib/registry-notary/config-state/antirollback.json",
        ])
        .expect("args parse");

        let Some(Command::Config {
            command: ConfigCommand::VerifyBundle(command),
        }) = args.command
        else {
            panic!("expected config verify-bundle command");
        };
        assert_eq!(
            command.bundle_dir,
            PathBuf::from("/etc/registry-notary/bundle")
        );
        assert_eq!(
            command.anchor_path,
            PathBuf::from("/etc/registry-notary/trust_anchor.json")
        );
        assert_eq!(
            command.state_path,
            PathBuf::from("/var/lib/registry-notary/config-state/antirollback.json")
        );
    }

    #[test]
    fn config_verify_bundle_cli_requires_state_path() {
        let err = Args::try_parse_from([
            "registry-notary",
            "config",
            "verify-bundle",
            "--bundle-dir",
            "/etc/registry-notary/bundle",
            "--anchor-path",
            "/etc/registry-notary/trust_anchor.json",
        ])
        .expect_err("missing state-path is rejected");

        assert!(err.to_string().contains("--state-path"));
    }

    #[test]
    fn config_apply_bundle_cli_is_removed() {
        let err = Args::try_parse_from(["registry-notary", "config", "apply-bundle"])
            .expect_err("apply-bundle is no longer a supported config subcommand");

        assert!(
            err.to_string().contains("unrecognized subcommand"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_info_reports_compiled_pkcs11_capability() {
        let info = build_info();
        assert_eq!(info["package"], "registry-notary");
        assert_eq!(
            info["capabilities"]["signing_providers"]["pkcs11"],
            json!(cfg!(feature = "pkcs11"))
        );
        let features = info["build_features"]
            .as_array()
            .expect("build_features is an array");
        assert_eq!(
            features.iter().any(|feature| feature == "pkcs11"),
            cfg!(feature = "pkcs11")
        );
    }

    #[tokio::test]
    async fn healthcheck_succeeds_for_success_status() {
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/healthz", get(|| async { StatusCode::OK })));
        let base_url = upstream.server_address().expect("upstream address");
        let url = format!("{}/healthz", base_url.as_str().trim_end_matches('/'));

        run_healthcheck(&url, Duration::from_secs(1))
            .await
            .expect("healthcheck succeeds");
    }

    #[tokio::test]
    async fn healthcheck_fails_for_non_success_status() {
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route(
                "/healthz",
                get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            ));
        let base_url = upstream.server_address().expect("upstream address");
        let url = format!("{}/healthz", base_url.as_str().trim_end_matches('/'));

        let err = run_healthcheck(&url, Duration::from_secs(1))
            .await
            .expect_err("healthcheck fails");
        assert!(err.to_string().contains("HTTP 503"));
    }

    #[test]
    fn generated_demo_issuer_key_is_parseable() {
        let jwk = demo_issuer_jwk("did:web:localhost#demo").expect("jwk generated");
        PrivateJwk::parse(&jwk).expect("generated JWK parses");
        assert!(!format!("{jwk:?}").contains("[redacted]"));
    }

    #[test]
    fn bind_override_replaces_config_bind() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.server.bind = "127.0.0.1:8081".parse().expect("socket addr parses");

        apply_bind_override(
            &mut config,
            Some("0.0.0.0:8080".parse().expect("socket addr parses")),
        );

        assert_eq!(
            config.server.bind,
            "0.0.0.0:8080"
                .parse::<SocketAddr>()
                .expect("socket addr parses")
        );
    }

    #[tokio::test]
    async fn run_server_compiles_runtime_before_binding_listener() {
        let held_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        let held_addr = held_listener
            .local_addr()
            .expect("test listener exposes local addr");
        let config_path = std::env::temp_dir().join(format!(
            "registry-notary-invalid-startup-{}.yaml",
            Ulid::new()
        ));
        let config = doctor_live_test_config("http://127.0.0.1:1");
        fs::write(
            &config_path,
            serde_norway::to_string(&config).expect("startup config serializes"),
        )
        .expect("invalid startup config writes");

        let error = run_server(&config_path, Some(held_addr), false)
            .await
            .expect_err("invalid runtime config fails before serving");
        let message = error.to_string();

        assert!(
            message.contains("TEST_DOCTOR_OAUTH_CLIENT_ID")
                || message.contains("TEST_DOCTOR_OAUTH_CLIENT_SECRET")
                || message.contains("audit.hash_secret_env"),
            "unexpected error: {message}"
        );
        assert!(
            !message.contains("Address already in use"),
            "server bound before compile failure: {message}"
        );

        let _ = fs::remove_file(config_path);
        drop(held_listener);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn run_server_fails_fast_when_active_signing_key_env_is_missing() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var(
            "TEST_STARTUP_API_HASH",
            "sha256:31f2999a69fa6301763a9f61eea44388a13318ce8b80a16a115a9efdb62b883b",
        );
        std::env::set_var(
            "TEST_STARTUP_AUDIT_HASH_SECRET",
            "registry-notary-startup-audit-secret-32-bytes",
        );
        std::env::remove_var("TEST_STARTUP_ISSUER_JWK");

        let held_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        let held_addr = held_listener
            .local_addr()
            .expect("test listener exposes local addr");
        let config_path = std::env::temp_dir().join(format!(
            "registry-notary-missing-signing-env-{}.yaml",
            Ulid::new()
        ));
        fs::write(
            &config_path,
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_STARTUP_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
  hash_secret_env: TEST_STARTUP_AUDIT_HASH_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_STARTUP_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
"#,
        )
        .expect("startup config writes");

        let error = run_server(&config_path, Some(held_addr), false)
            .await
            .expect_err("missing signing key env fails before serving");
        let message = error.to_string();

        assert!(
            message.contains("signing key 'issuer' is invalid")
                && message.contains("private_jwk_env is missing or empty"),
            "unexpected error: {message}"
        );
        assert!(
            !message.contains("Address already in use"),
            "server bound before signing key validation failed: {message}"
        );

        let _ = fs::remove_file(config_path);
        drop(held_listener);
        std::env::remove_var("TEST_STARTUP_API_HASH");
        std::env::remove_var("TEST_STARTUP_AUDIT_HASH_SECRET");
    }

    #[test]
    fn bind_cli_override_wins_over_env() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var("REGISTRY_NOTARY_BIND", "0.0.0.0:8080");
        let args = Args::try_parse_from([
            "registry-notary",
            "--bind",
            "127.0.0.1:9000",
            "explain-config",
        ])
        .expect("args parse");
        std::env::remove_var("REGISTRY_NOTARY_BIND");

        assert_eq!(
            args.bind,
            Some("127.0.0.1:9000".parse().expect("socket addr parses"))
        );
    }

    #[test]
    fn env_bind_override_is_loaded_by_cli() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var("REGISTRY_NOTARY_BIND", "0.0.0.0:8080");
        let args = Args::try_parse_from(["registry-notary", "explain-config"]).expect("args parse");
        std::env::remove_var("REGISTRY_NOTARY_BIND");

        assert_eq!(
            args.bind,
            Some("0.0.0.0:8080".parse().expect("socket addr parses"))
        );
    }

    #[test]
    fn redaction_covers_pin_key_and_credential_names() {
        let mut value = json!({
            "pin": "1234",
            "password_env": "PKCS12_PASSWORD_ENV_NAME",
            "key": "plain-key",
            "credential": "raw-credential",
            "credential_env": "SOURCE_CREDENTIAL",
            "api_keys": [{
                "id": "api-key-id",
                "scopes": ["claims:read"]
            }],
            "signing_keys": {
                "active": {
                    "status": "active",
                    "public_key_id": "public-key-id"
                }
            },
            "nested": {
                "public_key": "public-material",
                "source_credential": "source-secret",
                "safe": "visible"
            }
        });

        redact_value(&mut value);

        assert_eq!(value["pin"], json!("[redacted]"));
        assert_eq!(value["password_env"], json!("[redacted]"));
        assert_eq!(value["key"], json!("[redacted]"));
        assert_eq!(value["credential"], json!("[redacted]"));
        assert_eq!(value["credential_env"], json!("[redacted]"));
        assert_eq!(value["nested"]["public_key"], json!("[redacted]"));
        assert_eq!(value["nested"]["source_credential"], json!("[redacted]"));
        assert_eq!(value["nested"]["safe"], json!("visible"));
        assert_eq!(value["api_keys"][0]["id"], json!("api-key-id"));
        assert_eq!(value["api_keys"][0]["scopes"][0], json!("claims:read"));
        assert_eq!(value["signing_keys"]["active"]["status"], json!("active"));
        assert_eq!(
            value["signing_keys"]["active"]["public_key_id"],
            json!("[redacted]")
        );
    }

    #[test]
    fn local_file_audit_sink_emits_beta_tamper_evidence_warning() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "jsonl".to_string();

        let diagnostics = local_env_diagnostics(&config, &EnvFileReport::default());

        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.label.contains("local-chain-only"))
            .expect("audit file warning exists");
        assert!(warning.ok);
        assert!(warning.warning);
        assert!(warning
            .action
            .as_deref()
            .expect("warning has next action")
            .contains("off-host"));
    }

    #[test]
    fn attested_local_file_audit_sink_suppresses_beta_tamper_evidence_warning() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "jsonl".to_string();
        config.deployment.evidence.audit_offhost_shipping = true;

        let diagnostics = local_env_diagnostics(&config, &EnvFileReport::default());

        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.label.contains("local-chain-only")),
            "declaring off-host shipping must silence the local-chain-only warning"
        );
    }

    #[test]
    fn notary_audit_shipping_reports_stdout_sink_as_shipped() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "stdout");
        assert_eq!(shipping["shipping_target_configured"], true);
        assert_eq!(shipping["shipping_target"], "stdout");
        // A shipping target is declared but no ack cursor is configured.
        assert_eq!(shipping["shipping_health"], "unverified");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_reports_local_file_sink_without_attestation_as_unshipped() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "jsonl".to_string();
        config.deployment.evidence.audit_offhost_shipping = false;

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "file");
        assert_eq!(shipping["shipping_target_configured"], false);
        assert_eq!(shipping["shipping_target"], "none");
        // No shipping target is configured, so health is null.
        assert_eq!(shipping["shipping_health"], Value::Null);
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_reports_attested_local_file_sink_as_declared_external() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "file".to_string();
        config.deployment.evidence.audit_offhost_shipping = true;

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "file");
        assert_eq!(shipping["shipping_target_configured"], true);
        assert_eq!(shipping["shipping_target"], "declared_external");
        // declared_external with no ack cursor: shipping is declared but unobserved.
        assert_eq!(shipping["shipping_health"], "unverified");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_maps_unrecognized_sink_to_unknown() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "s3".to_string();

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "unknown");
        assert_eq!(shipping["shipping_target_configured"], false);
        assert_eq!(shipping["shipping_target"], "unknown");
        assert_eq!(shipping["shipping_health"], Value::Null);
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    /// Write a `registry.audit.ack_cursor.v1` cursor with `acked_at` and return
    /// its path, so doctor shipping-health tests can drive each observation.
    fn write_doctor_ack_cursor(tmp: &tempfile::TempDir, acked_at: &str) -> std::path::PathBuf {
        let path = tmp.path().join("ack-cursor.json");
        let body = format!(
            r#"{{"schema":"registry.audit.ack_cursor.v1","acked_at":"{acked_at}","last_acked_hash":"sha256:4444444444444444444444444444444444444444444444444444444444444444","writer":"test-shipper"}}"#
        );
        std::fs::write(&path, body).expect("ack cursor writes");
        path
    }

    #[test]
    fn notary_audit_shipping_reports_ok_for_fresh_cursor() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let acked_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("now formats");
        let cursor = write_doctor_ack_cursor(&tmp, &acked_at);
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "ok");
        assert_eq!(shipping["shipping_observed_at"], acked_at);
    }

    #[test]
    fn notary_audit_shipping_reports_stale_for_old_cursor() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // Far past the default 900s window relative to any plausible test clock.
        let cursor = write_doctor_ack_cursor(&tmp, "2026-06-04T09:59:00Z");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "stale");
        assert_eq!(shipping["shipping_observed_at"], "2026-06-04T09:59:00Z");
    }

    #[test]
    fn notary_audit_shipping_reports_missing_for_absent_cursor_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let cursor = tmp.path().join("does-not-exist.json");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "missing");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_reports_invalid_for_malformed_cursor_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let cursor = tmp.path().join("ack-cursor.json");
        std::fs::write(&cursor, "{ not valid json").expect("cursor writes");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "invalid");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn doctor_pkcs11_preflight_attempts_module_loading() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var(
            "TEST_DOCTOR_PKCS11_PUBLIC_JWK",
            r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm"}"#,
        );
        std::env::set_var("TEST_DOCTOR_PKCS11_PIN", "1234");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.evidence.signing_keys.insert(
            "hsm-key".to_string(),
            registry_notary_core::SigningKeyConfig {
                provider: SigningKeyProviderConfig::Pkcs11,
                alg: "EdDSA".to_string(),
                kid: "did:web:issuer.example#hsm".to_string(),
                status: registry_notary_core::SigningKeyStatus::Active,
                publish_until_unix_seconds: None,
                private_jwk_env: String::new(),
                public_jwk_env: "TEST_DOCTOR_PKCS11_PUBLIC_JWK".to_string(),
                module_path: "/definitely/missing/pkcs11.so".to_string(),
                token_label: "registry-notary".to_string(),
                pin_env: "TEST_DOCTOR_PKCS11_PIN".to_string(),
                key_label: "issuer-signing-key".to_string(),
                key_id_hex: "01ab23cd".to_string(),
                path: String::new(),
                password_env: String::new(),
            },
        );

        let diagnostic =
            pkcs11_preflight_diagnostic(&config).expect("active PKCS#11 key triggers preflight");

        assert!(!diagnostic.ok);
        assert!(diagnostic
            .label
            .contains("PKCS#11 signing preflight failed"));
        assert!(
            diagnostic.label.contains("could not load PKCS#11 module")
                || diagnostic
                    .label
                    .contains("provider 'pkcs11' is not enabled"),
            "unexpected diagnostic: {}",
            diagnostic.label
        );
        std::env::remove_var("TEST_DOCTOR_PKCS11_PUBLIC_JWK");
        std::env::remove_var("TEST_DOCTOR_PKCS11_PIN");
    }

    #[test]
    fn dci_diagnostics_skip_registry_data_api_bindings() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        let binding = config.evidence.claims[0]
            .source_bindings
            .get_mut("record")
            .expect("source binding exists");
        binding.connector = registry_notary_core::SourceConnectorKind::RegistryDataApi;

        let diagnostics = dci_diagnostics(&config, None);

        assert!(diagnostics.is_empty());
    }

    fn test_dci_options(demo_issuer: bool) -> InitDciOptions {
        InitDciOptions {
            base_url: "https://dci.example.test".to_string(),
            token_url: "https://dci.example.test/oauth2/client/token".to_string(),
            lookup_field: "SUBJECT_ID".to_string(),
            claim_id: "dci-record-exists".to_string(),
            claim_title: "DCI record exists".to_string(),
            demo_issuer,
            with_env_file: false,
            force: false,
            print_secrets: false,
        }
    }

    #[test]
    fn generated_dci_config_uses_explicit_dci_and_generic_oauth() {
        let yaml = dci_config_yaml(&test_dci_options(true));
        assert!(!yaml.contains("preset:"));
        assert!(yaml.contains("type: oauth2_client_credentials"));
        assert!(yaml.contains("client_id_env: DCI_CLIENT_ID"));
        assert!(yaml.contains("field: 'SUBJECT_ID'"));
        let config: StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&yaml).expect("generated config parses");
        config.validate().expect("generated config validates");
        let profile = config
            .evidence
            .credential_profiles
            .get("dci_record_sd_jwt")
            .expect("demo DCI credential profile exists");
        assert_eq!(profile.holder_binding.mode, "none");
        assert!(profile.holder_binding.proof_of_possession.is_none());
    }

    #[test]
    fn lightweight_schema_exposes_top_level_config_sections() {
        let schema = lightweight_schema();
        assert_eq!(schema["additionalProperties"], json!(false));
        assert!(schema["properties"]["evidence"].is_object());
        assert!(schema["properties"]["auth"].is_object());
    }

    #[test]
    fn dci_probe_body_uses_binding_lookup_field_for_idtype_value_queries_by_default() {
        let config: StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&dci_config_yaml(&test_dci_options(false)))
                .expect("generated config parses");
        let connection = config
            .evidence
            .source_connections
            .get("dci_registry")
            .expect("connection exists");
        let binding =
            first_dci_binding_for_connection(&config, "dci_registry").expect("dci binding exists");
        let body = dci_probe_body(
            &connection.effective_dci().expect("effective dci"),
            binding,
            "secret-subject-123",
            None,
        )
        .expect("body builds");
        assert_eq!(
            body["message"]["search_request"][0]["search_criteria"]["query"],
            json!({
                "type": "SUBJECT_ID",
                "value": "secret-subject-123"
            })
        );
    }

    #[test]
    fn dci_probe_body_allows_subject_id_type_override_for_idtype_value_queries() {
        let config: StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&dci_config_yaml(&test_dci_options(false)))
                .expect("generated config parses");
        let connection = config
            .evidence
            .source_connections
            .get("dci_registry")
            .expect("connection exists");
        let binding =
            first_dci_binding_for_connection(&config, "dci_registry").expect("dci binding exists");
        let body = dci_probe_body(
            &connection.effective_dci().expect("effective dci"),
            binding,
            "secret-subject-123",
            Some("NATIONAL_ID"),
        )
        .expect("body builds");
        assert_eq!(
            body["message"]["search_request"][0]["search_criteria"]["query"],
            json!({
                "type": "NATIONAL_ID",
                "value": "secret-subject-123"
            })
        );
    }

    #[test]
    fn doctor_source_url_preserves_base_path_prefix() {
        let url = source_url_for_cli("https://dci.example.test/api/v1", "/registry/sync/search")
            .expect("relative DCI path builds");

        assert_eq!(
            url.as_str(),
            "https://dci.example.test/api/v1/registry/sync/search"
        );
    }

    #[test]
    fn doctor_source_url_ignores_empty_relative_path_segments() {
        let url = source_url_for_cli("https://dci.example.test/api/v1/", "registry//sync/search")
            .expect("relative DCI path builds");

        assert_eq!(
            url.as_str(),
            "https://dci.example.test/api/v1/registry/sync/search"
        );
    }

    #[test]
    fn public_jwk_diagnostic_rejects_mismatched_kid() {
        let env = format!("TEST_REGISTRY_NOTARY_PUBLIC_JWK_{}", Ulid::new());
        unsafe {
            std::env::set_var(
                &env,
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYdkdABYXknkTDYUs_NflZt9-QJxBWpukhfQq8Q",
                    "alg": "EdDSA",
                    "kid": "did:web:issuer.example#wrong"
                })
                .to_string(),
            );
        }

        let diagnostic = check_public_jwk_env(
            &env,
            "hsm-key",
            "did:web:issuer.example#expected",
            "EdDSA",
            &EnvFileReport::default(),
        );
        unsafe {
            std::env::remove_var(&env);
        }

        assert!(!diagnostic.ok);
        assert!(diagnostic.label.contains("kid mismatch"));
    }

    #[test]
    fn public_jwk_diagnostic_rejects_missing_alg() {
        let env = format!("TEST_REGISTRY_NOTARY_PUBLIC_JWK_{}", Ulid::new());
        unsafe {
            std::env::set_var(
                &env,
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYdkdABYXknkTDYUs_NflZt9-QJxBWpukhfQq8Q",
                    "kid": "did:web:issuer.example#key-1"
                })
                .to_string(),
            );
        }

        let diagnostic = check_public_jwk_env(
            &env,
            "hsm-key",
            "did:web:issuer.example#key-1",
            "EdDSA",
            &EnvFileReport::default(),
        );
        unsafe {
            std::env::remove_var(&env);
        }

        assert!(!diagnostic.ok);
        assert!(diagnostic.label.contains("alg mismatch"));
    }

    #[test]
    fn local_jwk_diagnostic_rejects_mismatched_alg() {
        let env = format!("TEST_REGISTRY_NOTARY_PRIVATE_JWK_{}", Ulid::new());
        unsafe {
            std::env::set_var(
                &env,
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
                    "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
                    "alg": "RS256",
                    "kid": "did:web:issuer.example#key-1"
                })
                .to_string(),
            );
        }

        let diagnostic = check_local_jwk_env(
            &env,
            "issuer-key",
            "did:web:issuer.example#key-1",
            "EdDSA",
            &EnvFileReport::default(),
        );
        unsafe {
            std::env::remove_var(&env);
        }

        assert!(!diagnostic.ok);
        assert!(
            diagnostic.label.contains("alg mismatch")
                || diagnostic.label.contains("usable local JWK")
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_secret_file_overwrite_forces_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "registry-notary-secret-permissions-{}",
            Ulid::new()
        ));
        std::fs::write(&path, "old").expect("test file is written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("test file permissions are set");

        write_generated_file(&path, "secret", true, true).expect("secret file is overwritten");

        let mode = std::fs::metadata(&path)
            .expect("test file metadata")
            .permissions()
            .mode()
            & 0o777;
        std::fs::remove_file(&path).expect("test file is removed");
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn doctor_live_fetches_oauth_runs_dci_probe_and_redacts_subject_and_token() {
        std::env::set_var("TEST_DOCTOR_OAUTH_CLIENT_ID", "doctor-client");
        std::env::set_var("TEST_DOCTOR_OAUTH_CLIENT_SECRET", "doctor-secret");
        let state = DoctorLiveState::default();
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route("/oauth/token", post(test_oauth_token))
                .route("/registry/sync/search", post(test_dci_search))
                .with_state(state.clone()),
        );
        let base_url = upstream
            .server_address()
            .expect("upstream address")
            .to_string();
        let config = doctor_live_test_config(base_url.trim_end_matches('/'));
        let diagnostics = live_diagnostics(&config, Some("secret-subject-123"), None).await;

        assert!(
            state.token_called.load(Ordering::SeqCst),
            "doctor should call OAuth token endpoint"
        );
        assert!(
            state.dci_called.load(Ordering::SeqCst),
            "doctor should run DCI record probe"
        );
        assert!(
            diagnostics.iter().all(|diagnostic| diagnostic.ok),
            "expected all diagnostics ok: {diagnostics:?}"
        );
        let output = diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{} {}",
                    diagnostic.label,
                    diagnostic.action.as_deref().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!output.contains("secret-subject-123"));
        assert!(!output.contains("doctor-live-token"));

        std::env::remove_var("TEST_DOCTOR_OAUTH_CLIENT_ID");
        std::env::remove_var("TEST_DOCTOR_OAUTH_CLIENT_SECRET");
    }

    fn doctor_live_test_config(base_url: &str) -> StandaloneRegistryNotaryConfig {
        let raw = format!(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_API_HASH
      scopes: [dci:evidence_verification]
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: doctor-live-test
  source_connections:
    dci_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      source_auth:
        type: oauth2_client_credentials
        token_url: "{base_url}/oauth/token"
        client_id_env: TEST_DOCTOR_OAUTH_CLIENT_ID
        client_secret_env: TEST_DOCTOR_OAUTH_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
  claims:
    - id: dci-record-exists
      title: DCI record exists
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      source_bindings:
        record:
          connector: dci
          connection: dci_registry
          required_scope: dci:evidence_verification
          dataset: registry_records
          entity: record
          lookup:
            input: target.id
            field: SUBJECT_ID
            op: eq
            cardinality: one
          fields:
            id:
              field: id
              type: string
              required: false
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
        );
        serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&raw).expect("config parses")
    }

    #[test]
    fn doctor_parse_expanded_config_surfaces_disclosure_default_violation() {
        // GH#170 / RS-DM-CLAIM Section 10: `registry-notary doctor` calls
        // parse_expanded_config (see the `doctor` function above), which now
        // rejects a disclosure default that isn't a member of the claim's
        // allowed set (REQ-DM-CLAIM-008) at load instead of loading cleanly
        // and surfacing the inconsistency only when a result is rendered.
        let raw = r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_API_HASH
      scopes: [dci:evidence_verification]
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: doctor-disclosure-test
  source_connections:
    dci_registry:
      base_url: "https://dci.example.test"
      source_auth:
        type: oauth2_client_credentials
        token_url: "https://dci.example.test/oauth/token"
        client_id_env: TEST_DOCTOR_OAUTH_CLIENT_ID
        client_secret_env: TEST_DOCTOR_OAUTH_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
  claims:
    - id: dci-record-exists
      title: DCI record exists
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      source_bindings:
        record:
          connector: dci
          connection: dci_registry
          required_scope: dci:evidence_verification
          dataset: registry_records
          entity: record
          lookup:
            input: target.id
            field: SUBJECT_ID
            op: eq
            cardinality: one
          fields:
            id:
              field: id
              type: string
              required: false
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#;

        let err = parse_expanded_config(raw)
            .expect_err("disclosure default outside allowed must fail at the doctor entrypoint");
        let message = err.to_string();
        assert!(
            message.contains("dci-record-exists") && message.contains("disclosure"),
            "doctor-facing error must name the offending claim id and field: {message}"
        );
    }
}
