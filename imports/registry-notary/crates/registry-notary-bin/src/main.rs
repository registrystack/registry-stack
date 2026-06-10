// SPDX-License-Identifier: Apache-2.0
//! Registry Notary process entrypoint.

mod serve;

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Args as ClapArgs, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use registry_notary_core::{
    Oauth2ClientCredentialsSourceAuthConfig, RegistryNotaryAdminListenerMode,
    SigningKeyProviderConfig, SourceAuthConfig, StandaloneRegistryNotaryConfig,
};
use registry_notary_server::config_governed::{
    parse_candidate_config, resolve_tuf_config_candidate, ConfigGovernanceContext,
    LocalTufConfigTargetRequest, RemoteTufConfigTargetRequest, TufConfigTargetRequest,
};
use registry_notary_server::{
    compile_notary_runtime, notary_router_from_runtime, notary_routers_from_runtime,
    openapi_document, EvidenceIssuerRegistry,
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, PublicJwk};
use registry_platform_httputil::{url as httputil_url, FetchUrlPolicy};
use serde_json::{json, Value};
use serve::{serve_listener, ServeLimits};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use ulid::Ulid;

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
        /// Print resolved config with no secret values.
        #[arg(long)]
        show_expanded_config: bool,
    },
    /// Print resolved config and required env vars.
    ExplainConfig,
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
    /// Verify a local or remote TUF-profile signed configuration target.
    VerifyBundle(ConfigVerifyBundleArgs),
    /// Apply a local or remote TUF-profile signed configuration target through the admin API.
    ApplyBundle(ConfigApplyBundleArgs),
}

#[derive(Debug, Clone, ClapArgs)]
struct ConfigVerifyBundleArgs {
    /// Local TUF root metadata path.
    #[arg(long)]
    root_path: PathBuf,
    /// Local TUF metadata directory.
    #[arg(long)]
    metadata_dir: Option<PathBuf>,
    /// Local TUF targets directory.
    #[arg(long)]
    targets_dir: Option<PathBuf>,
    /// Remote TUF metadata base URL.
    #[arg(long)]
    metadata_base_url: Option<String>,
    /// Remote TUF targets base URL.
    #[arg(long)]
    targets_base_url: Option<String>,
    /// Persistent TUF datastore directory.
    #[arg(long)]
    datastore_dir: PathBuf,
    /// Target filename to verify.
    #[arg(long)]
    target_name: String,
    /// Allow HTTP loopback remote TUF repositories for tests and local development.
    #[arg(long)]
    allow_dev_insecure_fetch_urls: bool,
}

#[derive(Debug, Clone, ClapArgs)]
struct ConfigApplyBundleArgs {
    /// Admin API base URL.
    #[arg(long)]
    admin_url: String,
    /// Environment variable containing the admin bearer token.
    #[arg(long)]
    admin_token_env: String,
    /// Local TUF root metadata path.
    #[arg(long)]
    root_path: PathBuf,
    /// Local TUF metadata directory.
    #[arg(long)]
    metadata_dir: Option<PathBuf>,
    /// Local TUF targets directory.
    #[arg(long)]
    targets_dir: Option<PathBuf>,
    /// Remote TUF metadata base URL.
    #[arg(long)]
    metadata_base_url: Option<String>,
    /// Remote TUF targets base URL.
    #[arg(long)]
    targets_base_url: Option<String>,
    /// Persistent TUF datastore directory.
    #[arg(long)]
    datastore_dir: PathBuf,
    /// Target filename to apply.
    #[arg(long)]
    target_name: String,
    /// Allow HTTP loopback remote TUF repositories for tests and local development.
    #[arg(long)]
    allow_dev_insecure_fetch_urls: bool,
    /// Allow plaintext HTTP for the admin apply URL in local development.
    #[arg(long)]
    allow_insecure_admin_url: bool,
    /// Apply-only reference for a matching local root-transition approval record.
    #[arg(long)]
    local_approval_reference: Option<String>,
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

#[derive(Debug)]
struct Diagnostic {
    ok: bool,
    warning: bool,
    label: String,
    action: Option<String>,
}

impl Diagnostic {
    fn ok(label: impl Into<String>) -> Self {
        Self {
            ok: true,
            warning: false,
            label: label.into(),
            action: None,
        }
    }

    fn warn(label: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            ok: true,
            warning: true,
            label: label.into(),
            action: Some(action.into()),
        }
    }

    fn fail(label: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            ok: false,
            warning: false,
            label: label.into(),
            action: Some(action.into()),
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
            run_server(config_path, args.bind).await?;
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
                },
            )
            .await?;
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Some(Command::ExplainConfig) => {
            let config_path = required_config_path(args.config.as_deref())?;
            explain_config(config_path, &env_report, args.bind)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Config {
            command: ConfigCommand::VerifyBundle(verify_args),
        }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            config_verify_bundle(config_path, verify_args).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Config {
            command: ConfigCommand::ApplyBundle(apply_args),
        }) => {
            config_apply_bundle(apply_args).await?;
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
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,registry_notary_server=debug,registry_notary_bin=debug")
        }))
        .init();

    let mut config = load_expanded_config(config_path)?;
    apply_bind_override(&mut config, bind_override);
    let bind = config.server.bind;
    let admin_mode = config.server.admin_listener.mode;
    let admin_bind = config.server.admin_listener.bind;
    let serve_limits = ServeLimits::from_config(&config.server);
    let runtime = compile_notary_runtime(config)?;
    match admin_mode {
        RegistryNotaryAdminListenerMode::Dedicated => {
            let routers = notary_routers_from_runtime(runtime);
            let public_listener = tokio::net::TcpListener::bind(bind).await?;
            let public_addr: SocketAddr = public_listener.local_addr()?;
            let admin_listener = tokio::net::TcpListener::bind(admin_bind).await?;
            let admin_addr: SocketAddr = admin_listener.local_addr()?;
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
            let app = notary_router_from_runtime(runtime)
                .layer(TraceLayer::new_for_http().make_span_with(http_trace_span));
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let local_addr: SocketAddr = listener.local_addr()?;
            tracing::info!(
                %local_addr,
                build_features = ?compiled_build_features(),
                "registry notary listening"
            );

            serve_listener(listener, app, serve_limits, shutdown_signal()).await?;
        }
        RegistryNotaryAdminListenerMode::Disabled => {
            let app = notary_routers_from_runtime(runtime)
                .public
                .layer(TraceLayer::new_for_http().make_span_with(http_trace_span));
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let local_addr: SocketAddr = listener.local_addr()?;
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
    config_path: &Path,
    args: ConfigVerifyBundleArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = tuf_config_target_request_from_cli(&args)?;
    let current_config = load_expanded_config(config_path)?;
    let resolved = resolve_tuf_config_candidate(
        &request,
        &ConfigGovernanceContext::from_config(&current_config),
    )
    .await?;
    let candidate_config = parse_candidate_config(&resolved.config_yaml)
        .map_err(|detail| io::Error::new(io::ErrorKind::InvalidData, detail))?;
    let _compiled = compile_notary_runtime(candidate_config)?;

    let report = json!({
        "result": "verified",
        "source": resolved.source_label(),
        "target_name": args.target_name,
        "bundle_id": resolved.bundle_id,
        "stream_id": resolved.stream_id,
        "sequence": resolved.sequence,
        "previous_config_hash": resolved.previous_config_hash,
        "config_hash": resolved.internal_config_hash(),
        "root_version": resolved.root_version,
        "tuf_root_sha256": resolved.tuf_root_sha256,
        "change_classes": resolved.change_classes.into_iter().collect::<Vec<_>>(),
        "signer_kids": resolved.signer_kids.into_iter().collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn config_apply_bundle(
    args: ConfigApplyBundleArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = admin_bearer_token_from_env(&args.admin_token_env)?;
    let url = admin_config_apply_url(&args.admin_url, args.allow_insecure_admin_url)?;
    let body = config_apply_bundle_request_body(&args)?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()?
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;
    let status = response.status();
    let response_bytes = response.bytes().await?;
    let response_json: Value = serde_json::from_slice(&response_bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("admin config apply response was not JSON: {err}"),
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&response_json)?);
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("admin config apply returned HTTP {status}").into())
    }
}

fn admin_bearer_token_from_env(env_name: &str) -> Result<String, io::Error> {
    if !valid_env_key(env_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid --admin-token-env value: {env_name}"),
        ));
    }
    let token = std::env::var(env_name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("admin bearer token env var {env_name} is not set"),
        )
    })?;
    let token = token.trim();
    if token.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("admin bearer token env var {env_name} is empty"),
        ));
    }
    Ok(token.to_string())
}

fn admin_config_apply_url(
    admin_url: &str,
    allow_insecure_admin_url: bool,
) -> Result<reqwest::Url, io::Error> {
    let admin_url = admin_url.trim();
    if admin_url.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--admin-url must not be empty",
        ));
    }
    let url = format!("{}/admin/v1/config/apply", admin_url.trim_end_matches('/'));
    let url = reqwest::Url::parse(&url).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--admin-url did not form a valid admin apply URL: {err}"),
        )
    })?;
    if url.scheme() == "http" {
        if !allow_insecure_admin_url {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--admin-url must use https unless --allow-insecure-admin-url is set for local development",
            ));
        }
        if !is_loopback_admin_url(&url) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--allow-insecure-admin-url only permits http admin URLs on localhost or loopback addresses",
            ));
        }
    }
    Ok(url)
}

fn is_loopback_admin_url(url: &reqwest::Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .map(|addr| addr.is_loopback())
                .unwrap_or(false)
    })
}

fn config_apply_bundle_request_body(args: &ConfigApplyBundleArgs) -> Result<Value, io::Error> {
    let mut body = json!({
        "tuf": tuf_config_target_json_from_apply_cli(args)?,
    });
    if let Some(reference) = &args.local_approval_reference {
        body["local_approval_reference"] = Value::String(reference.clone());
    }
    Ok(body)
}

fn tuf_config_target_json_from_apply_cli(args: &ConfigApplyBundleArgs) -> Result<Value, io::Error> {
    let has_local_source = args.metadata_dir.is_some() || args.targets_dir.is_some();
    let has_remote_source = args.metadata_base_url.is_some()
        || args.targets_base_url.is_some()
        || args.allow_dev_insecure_fetch_urls;

    if has_local_source && has_remote_source {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUF request must choose exactly one local or remote source shape",
        ));
    }

    if has_remote_source {
        let metadata_base_url = args.metadata_base_url.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--metadata-base-url is required for remote TUF apply",
            )
        })?;
        let targets_base_url = args.targets_base_url.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--targets-base-url is required for remote TUF apply",
            )
        })?;
        return Ok(json!({
            "root_path": path_for_json(&args.root_path),
            "metadata_base_url": metadata_base_url,
            "targets_base_url": targets_base_url,
            "datastore_dir": path_for_json(&args.datastore_dir),
            "target_name": &args.target_name,
            "allow_dev_insecure_fetch_urls": args.allow_dev_insecure_fetch_urls,
        }));
    }

    let metadata_dir = args.metadata_dir.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--metadata-dir is required for local TUF apply",
        )
    })?;
    let targets_dir = args.targets_dir.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--targets-dir is required for local TUF apply",
        )
    })?;
    Ok(json!({
        "root_path": path_for_json(&args.root_path),
        "metadata_dir": path_for_json(&metadata_dir),
        "targets_dir": path_for_json(&targets_dir),
        "datastore_dir": path_for_json(&args.datastore_dir),
        "target_name": &args.target_name,
    }))
}

fn path_for_json(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn tuf_config_target_request_from_cli(
    args: &ConfigVerifyBundleArgs,
) -> Result<TufConfigTargetRequest, io::Error> {
    let has_local_source = args.metadata_dir.is_some() || args.targets_dir.is_some();
    let has_remote_source = args.metadata_base_url.is_some()
        || args.targets_base_url.is_some()
        || args.allow_dev_insecure_fetch_urls;

    if has_local_source && has_remote_source {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUF request must choose exactly one local or remote source shape",
        ));
    }

    if has_remote_source {
        let metadata_base_url = args.metadata_base_url.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--metadata-base-url is required for remote TUF verification",
            )
        })?;
        let targets_base_url = args.targets_base_url.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--targets-base-url is required for remote TUF verification",
            )
        })?;
        return Ok(TufConfigTargetRequest::Remote(
            RemoteTufConfigTargetRequest {
                root_path: args.root_path.clone(),
                metadata_base_url,
                targets_base_url,
                datastore_dir: args.datastore_dir.clone(),
                target_name: args.target_name.clone(),
                allow_dev_insecure_fetch_urls: args.allow_dev_insecure_fetch_urls,
            },
        ));
    }

    let metadata_dir = args.metadata_dir.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--metadata-dir is required for local TUF verification",
        )
    })?;
    let targets_dir = args.targets_dir.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--targets-dir is required for local TUF verification",
        )
    })?;
    Ok(TufConfigTargetRequest::Local(LocalTufConfigTargetRequest {
        root_path: args.root_path.clone(),
        metadata_dir,
        targets_dir,
        datastore_dir: args.datastore_dir.clone(),
        target_name: args.target_name.clone(),
    }))
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

fn load_expanded_config(
    config_path: &Path,
) -> Result<StandaloneRegistryNotaryConfig, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(config_path)?;
    let expanded = expand_config_env_vars(&raw)?;
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(&expanded)?;
    config.validate()?;
    Ok(config)
}

#[derive(Debug)]
struct ConfigEnvExpansionError(String);

impl fmt::Display for ConfigEnvExpansionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigEnvExpansionError {}

fn expand_config_env_vars(raw: &str) -> Result<String, ConfigEnvExpansionError> {
    let mut expanded = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(ConfigEnvExpansionError(
                "unterminated ${...} expression in config".to_string(),
            ));
        };
        let expression = &after_start[..end];
        expanded.push_str(&resolve_config_env_expression(expression)?);
        rest = &after_start[end + 1..];
    }
    expanded.push_str(rest);
    Ok(expanded)
}

fn resolve_config_env_expression(expression: &str) -> Result<String, ConfigEnvExpansionError> {
    let (name, operator, fallback) = if let Some((name, fallback)) = expression.split_once(":-") {
        (name, ":-", fallback)
    } else if let Some((name, fallback)) = expression.split_once(":?") {
        (name, ":?", fallback)
    } else {
        (expression, "", "")
    };
    if !valid_env_key(name) {
        return Err(ConfigEnvExpansionError(format!(
            "invalid env var name in config expression: {name}"
        )));
    }

    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ if operator == ":-" => Ok(fallback.to_string()),
        _ if operator == ":?" => {
            let message = if fallback.trim().is_empty() {
                format!("missing required env var {name}")
            } else {
                fallback.to_string()
            };
            Err(ConfigEnvExpansionError(message))
        }
        _ => Err(ConfigEnvExpansionError(format!(
            "missing required env var {name}"
        ))),
    }
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
}

async fn doctor(
    config_path: &Path,
    env_report: &EnvFileReport,
    bind_override: Option<SocketAddr>,
    options: DoctorOptions,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut diagnostics = Vec::new();
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
            print_diagnostics(&diagnostics);
            return Ok(false);
        }
    };
    let parsed = match serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&raw) {
        Ok(config) => {
            diagnostics.push(Diagnostic::ok("config YAML parsed"));
            let mut config = config;
            apply_bind_override(&mut config, bind_override);
            Some(config)
        }
        Err(err) => {
            diagnostics.push(Diagnostic::fail(
                format!("config YAML parse failed: {err}"),
                "fix the YAML syntax and field names",
            ));
            None
        }
    };
    let config = match parsed {
        Some(config) => {
            match config.validate() {
                Ok(()) => diagnostics.push(Diagnostic::ok("config semantics validated")),
                Err(err) => diagnostics.push(Diagnostic::fail(
                    format!("config semantic validation failed: {err}"),
                    "fix the reported config relationship before starting the server",
                )),
            }
            Some(config)
        }
        None => None,
    };
    if let Some(config) = &config {
        diagnostics.extend(local_env_diagnostics(config, env_report));
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
            println!(
                "{}",
                serde_json::to_string_pretty(&redacted_config(config))?
            );
        }
    }
    print_diagnostics(&diagnostics);
    Ok(diagnostics.iter().all(|diag| diag.ok))
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
    if matches!(config.audit.sink.as_str(), "file" | "jsonl") {
        diagnostics.push(Diagnostic::warn(
            "audit file/jsonl sink is local-chain-only",
            "for beta tamper-evidence, ship audit envelopes off-host via stdout/syslog or publish external head/tail anchors",
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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_expanded_config(config_path)?;
    apply_bind_override(&mut config, bind_override);
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
    Ok(())
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
        commitment: sha256:0000000000000000000000000000000000000000000000000000000000000000
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

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    struct DoctorLiveState {
        token_called: Arc<AtomicBool>,
        dci_called: Arc<AtomicBool>,
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

        assert!(expanded.contains("base_url: https://upstream.example"));
        assert!(expanded.contains("optional: fallback"));
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
    fn build_info_cli_parses() {
        let args = Args::try_parse_from(["registry-notary", "build-info"]).expect("args parse");
        assert!(matches!(args.command, Some(Command::BuildInfo)));
    }

    #[test]
    fn config_verify_bundle_cli_accepts_local_tuf_flags() {
        let args = Args::try_parse_from([
            "registry-notary",
            "--config",
            "/etc/registry-notary/current.yaml",
            "config",
            "verify-bundle",
            "--root-path",
            "/etc/registry-notary/tuf/metadata/1.root.json",
            "--metadata-dir",
            "/etc/registry-notary/tuf/metadata",
            "--targets-dir",
            "/etc/registry-notary/tuf/targets",
            "--datastore-dir",
            "/var/lib/registry-notary/tuf",
            "--target-name",
            "registry-notary.yaml",
        ])
        .expect("args parse");

        assert_eq!(
            args.config,
            Some(PathBuf::from("/etc/registry-notary/current.yaml"))
        );
        let Some(Command::Config {
            command: ConfigCommand::VerifyBundle(command),
        }) = args.command
        else {
            panic!("expected config verify-bundle command");
        };
        assert_eq!(
            command.root_path,
            PathBuf::from("/etc/registry-notary/tuf/metadata/1.root.json")
        );
        assert_eq!(
            command.metadata_dir,
            Some(PathBuf::from("/etc/registry-notary/tuf/metadata"))
        );
        assert_eq!(
            command.targets_dir,
            Some(PathBuf::from("/etc/registry-notary/tuf/targets"))
        );
        assert_eq!(
            command.datastore_dir,
            PathBuf::from("/var/lib/registry-notary/tuf")
        );
        assert_eq!(command.target_name, "registry-notary.yaml");
        assert_eq!(command.metadata_base_url, None);
        assert_eq!(command.targets_base_url, None);
        assert!(!command.allow_dev_insecure_fetch_urls);
    }

    #[test]
    fn config_verify_bundle_cli_accepts_remote_tuf_flags() {
        let args = Args::try_parse_from([
            "registry-notary",
            "--config",
            "/etc/registry-notary/current.yaml",
            "config",
            "verify-bundle",
            "--root-path",
            "/etc/registry-notary/tuf/metadata/1.root.json",
            "--metadata-base-url",
            "https://config.example.gov/metadata",
            "--targets-base-url",
            "https://config.example.gov/targets",
            "--datastore-dir",
            "/var/lib/registry-notary/tuf",
            "--target-name",
            "registry-notary.yaml",
            "--allow-dev-insecure-fetch-urls",
        ])
        .expect("args parse");

        let Some(Command::Config {
            command: ConfigCommand::VerifyBundle(command),
        }) = args.command
        else {
            panic!("expected config verify-bundle command");
        };
        assert_eq!(
            command.root_path,
            PathBuf::from("/etc/registry-notary/tuf/metadata/1.root.json")
        );
        assert_eq!(command.metadata_dir, None);
        assert_eq!(command.targets_dir, None);
        assert_eq!(
            command.metadata_base_url.as_deref(),
            Some("https://config.example.gov/metadata")
        );
        assert_eq!(
            command.targets_base_url.as_deref(),
            Some("https://config.example.gov/targets")
        );
        assert_eq!(
            command.datastore_dir,
            PathBuf::from("/var/lib/registry-notary/tuf")
        );
        assert_eq!(command.target_name, "registry-notary.yaml");
        assert!(command.allow_dev_insecure_fetch_urls);
    }

    #[test]
    fn config_verify_bundle_cli_requires_target_name() {
        let err = Args::try_parse_from([
            "registry-notary",
            "--config",
            "/etc/registry-notary/current.yaml",
            "config",
            "verify-bundle",
            "--root-path",
            "/etc/registry-notary/tuf/metadata/1.root.json",
            "--metadata-dir",
            "/etc/registry-notary/tuf/metadata",
            "--targets-dir",
            "/etc/registry-notary/tuf/targets",
            "--datastore-dir",
            "/var/lib/registry-notary/tuf",
        ])
        .expect_err("missing target-name is rejected");

        assert!(err.to_string().contains("--target-name"));
    }

    #[test]
    fn config_apply_bundle_cli_accepts_local_tuf_flags_without_config() {
        let args = Args::try_parse_from([
            "registry-notary",
            "config",
            "apply-bundle",
            "--admin-url",
            "https://notary-admin.example.gov",
            "--admin-token-env",
            "REGISTRY_NOTARY_ADMIN_TOKEN",
            "--root-path",
            "/etc/registry-notary/tuf/metadata/1.root.json",
            "--metadata-dir",
            "/etc/registry-notary/tuf/metadata",
            "--targets-dir",
            "/etc/registry-notary/tuf/targets",
            "--datastore-dir",
            "/var/lib/registry-notary/tuf",
            "--target-name",
            "registry-notary.yaml",
            "--local-approval-reference",
            "ROOT-2026-Q2",
        ])
        .expect("args parse");

        assert_eq!(args.config, None);
        let Some(Command::Config {
            command: ConfigCommand::ApplyBundle(command),
        }) = args.command
        else {
            panic!("expected config apply-bundle command");
        };
        assert_eq!(command.admin_url, "https://notary-admin.example.gov");
        assert_eq!(command.admin_token_env, "REGISTRY_NOTARY_ADMIN_TOKEN");
        assert_eq!(
            command.root_path,
            PathBuf::from("/etc/registry-notary/tuf/metadata/1.root.json")
        );
        assert_eq!(
            command.metadata_dir,
            Some(PathBuf::from("/etc/registry-notary/tuf/metadata"))
        );
        assert_eq!(
            command.targets_dir,
            Some(PathBuf::from("/etc/registry-notary/tuf/targets"))
        );
        assert_eq!(
            command.datastore_dir,
            PathBuf::from("/var/lib/registry-notary/tuf")
        );
        assert_eq!(command.target_name, "registry-notary.yaml");
        assert_eq!(
            command.local_approval_reference.as_deref(),
            Some("ROOT-2026-Q2")
        );
        assert_eq!(command.metadata_base_url, None);
        assert_eq!(command.targets_base_url, None);
        assert!(!command.allow_dev_insecure_fetch_urls);
    }

    #[test]
    fn config_apply_bundle_cli_accepts_remote_tuf_flags() {
        let args = Args::try_parse_from([
            "registry-notary",
            "config",
            "apply-bundle",
            "--admin-url",
            "https://notary-admin.example.gov",
            "--admin-token-env",
            "REGISTRY_NOTARY_ADMIN_TOKEN",
            "--root-path",
            "/etc/registry-notary/tuf/metadata/1.root.json",
            "--metadata-base-url",
            "https://config.example.gov/metadata",
            "--targets-base-url",
            "https://config.example.gov/targets",
            "--datastore-dir",
            "/var/lib/registry-notary/tuf",
            "--target-name",
            "registry-notary.yaml",
            "--allow-dev-insecure-fetch-urls",
        ])
        .expect("args parse");

        let Some(Command::Config {
            command: ConfigCommand::ApplyBundle(command),
        }) = args.command
        else {
            panic!("expected config apply-bundle command");
        };
        assert_eq!(command.metadata_dir, None);
        assert_eq!(command.targets_dir, None);
        assert_eq!(
            command.metadata_base_url.as_deref(),
            Some("https://config.example.gov/metadata")
        );
        assert_eq!(
            command.targets_base_url.as_deref(),
            Some("https://config.example.gov/targets")
        );
        assert!(command.allow_dev_insecure_fetch_urls);
        assert!(!command.allow_insecure_admin_url);
    }

    #[test]
    fn config_apply_bundle_cli_parses_insecure_admin_url_dev_opt_in() {
        let args = Args::try_parse_from([
            "registry-notary",
            "config",
            "apply-bundle",
            "--admin-url",
            "http://127.0.0.1:8080",
            "--allow-insecure-admin-url",
            "--admin-token-env",
            "REGISTRY_NOTARY_ADMIN_TOKEN",
            "--root-path",
            "/etc/registry-notary/tuf/metadata/1.root.json",
            "--metadata-dir",
            "/etc/registry-notary/tuf/metadata",
            "--targets-dir",
            "/etc/registry-notary/tuf/targets",
            "--datastore-dir",
            "/var/lib/registry-notary/tuf",
            "--target-name",
            "registry-notary.yaml",
        ])
        .expect("args parse");

        let Some(Command::Config {
            command: ConfigCommand::ApplyBundle(command),
        }) = args.command
        else {
            panic!("expected config apply-bundle command");
        };
        assert_eq!(command.admin_url, "http://127.0.0.1:8080");
        assert!(command.allow_insecure_admin_url);
    }

    #[test]
    fn admin_apply_url_rejects_remote_plaintext_even_with_dev_opt_in() {
        let error = admin_config_apply_url("http://notary-admin.example.gov", true)
            .expect_err("remote plaintext admin URL must be rejected");

        assert!(
            error
                .to_string()
                .contains("localhost or loopback addresses"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn admin_apply_url_accepts_loopback_plaintext_only_with_dev_opt_in() {
        let error = admin_config_apply_url("http://127.0.0.1:8080", false)
            .expect_err("loopback plaintext still requires explicit opt-in");
        assert!(error.to_string().contains("--allow-insecure-admin-url"));

        let url = admin_config_apply_url("http://localhost:8080", true)
            .expect("localhost plaintext is allowed with explicit opt-in");
        assert_eq!(url.as_str(), "http://localhost:8080/admin/v1/config/apply");
    }

    #[test]
    fn config_apply_bundle_request_body_builds_local_tuf_json() {
        let args = ConfigApplyBundleArgs {
            admin_url: "https://notary-admin.example.gov".to_string(),
            admin_token_env: "REGISTRY_NOTARY_ADMIN_TOKEN".to_string(),
            root_path: PathBuf::from("/etc/registry-notary/tuf/metadata/1.root.json"),
            metadata_dir: Some(PathBuf::from("/etc/registry-notary/tuf/metadata")),
            targets_dir: Some(PathBuf::from("/etc/registry-notary/tuf/targets")),
            metadata_base_url: None,
            targets_base_url: None,
            datastore_dir: PathBuf::from("/var/lib/registry-notary/tuf"),
            target_name: "registry-notary.yaml".to_string(),
            allow_dev_insecure_fetch_urls: false,
            allow_insecure_admin_url: false,
            local_approval_reference: Some("ROOT-2026-Q2".to_string()),
        };

        let body = config_apply_bundle_request_body(&args).expect("body builds");

        assert_eq!(
            body,
            json!({
                "tuf": {
                    "root_path": "/etc/registry-notary/tuf/metadata/1.root.json",
                    "metadata_dir": "/etc/registry-notary/tuf/metadata",
                    "targets_dir": "/etc/registry-notary/tuf/targets",
                    "datastore_dir": "/var/lib/registry-notary/tuf",
                    "target_name": "registry-notary.yaml"
                },
                "local_approval_reference": "ROOT-2026-Q2"
            })
        );
    }

    #[test]
    fn config_apply_bundle_request_body_builds_remote_tuf_json() {
        let args = ConfigApplyBundleArgs {
            admin_url: "https://notary-admin.example.gov".to_string(),
            admin_token_env: "REGISTRY_NOTARY_ADMIN_TOKEN".to_string(),
            root_path: PathBuf::from("/etc/registry-notary/tuf/metadata/1.root.json"),
            metadata_dir: None,
            targets_dir: None,
            metadata_base_url: Some("https://config.example.gov/metadata".to_string()),
            targets_base_url: Some("https://config.example.gov/targets".to_string()),
            datastore_dir: PathBuf::from("/var/lib/registry-notary/tuf"),
            target_name: "registry-notary.yaml".to_string(),
            allow_dev_insecure_fetch_urls: true,
            allow_insecure_admin_url: false,
            local_approval_reference: None,
        };

        let body = config_apply_bundle_request_body(&args).expect("body builds");

        assert_eq!(
            body,
            json!({
                "tuf": {
                    "root_path": "/etc/registry-notary/tuf/metadata/1.root.json",
                    "metadata_base_url": "https://config.example.gov/metadata",
                    "targets_base_url": "https://config.example.gov/targets",
                    "datastore_dir": "/var/lib/registry-notary/tuf",
                    "target_name": "registry-notary.yaml",
                    "allow_dev_insecure_fetch_urls": true
                }
            })
        );
    }

    #[test]
    fn build_info_reports_compiled_pkcs11_capability() {
        let info = build_info();
        assert_eq!(info["package"], "registry-notary-bin");
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

        let error = run_server(&config_path, Some(held_addr))
            .await
            .expect_err("invalid runtime config fails before serving");
        let message = error.to_string();

        assert!(
            message.contains("TEST_DOCTOR_OAUTH_CLIENT_ID")
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
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_API_HASH
        commitment: sha256:31f2999a69fa6301763a9f61eea44388a13318ce8b80a16a115a9efdb62b883b
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
}
