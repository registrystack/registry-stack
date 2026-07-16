// SPDX-License-Identifier: Apache-2.0
//! Registry Notary process entrypoint.

mod boot;
mod commands;
mod config_loader;
mod doctor;
mod env_file;
mod explain_config;
mod logging;
mod serve;

use boot::*;
use commands::*;
use config_loader::*;
use doctor::*;
use env_file::*;
use explain_config::*;
use logging::*;

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
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
    ConfigValueClassification, LiveApplyClass, ReportStatus, RequiredEnvStatus,
};
use registry_notary_core::deployment::{
    evaluate_gates, DeploymentFindingStatus, DeploymentProfile, EvaluatedFinding,
};
use registry_notary_core::{
    deprecated_config_fields, ConfigAuditEvent, ConfigTrustConfig, RegistryNotaryAdminListenerMode,
    SigningKeyProviderConfig, StandaloneRegistryNotaryConfig, STATE_STORAGE_POSTGRESQL,
};
use registry_notary_server::{
    compile_notary_runtime_with_provenance, notary_routers_from_runtime,
    notary_shared_router_from_runtime, openapi_document, verify_relay_from_config,
    EvidenceIssuerRegistry, StandaloneServerError,
};
use registry_platform_config::{
    expand_config_env_vars, reject_deprecated_config_fields, verify_config_bundle,
    ConfigBundleError, VerifiedConfigBundle,
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, PublicJwk};
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
    /// Validate config, env-backed secrets, Relay activation, and VC wiring.
    Doctor {
        /// Verify Relay activation for Registry-backed claims.
        #[arg(long)]
        live: bool,
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
    /// Install or attest the Notary-owned PostgreSQL correctness state.
    State {
        #[command(subcommand)]
        command: StateCommand,
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

#[derive(Debug, Subcommand)]
enum StateCommand {
    /// Install or attest the forward-only PostgreSQL state schema.
    Install(StateInstallArgs),
    /// Connect as the runtime role and attest readiness without mutation.
    Doctor,
}

#[derive(Debug, Clone, ClapArgs)]
struct StateInstallArgs {
    /// Environment variable containing the migration-login PostgreSQL URL.
    #[arg(long)]
    migration_url_env: String,
    /// NOLOGIN role that owns the Notary schemas and functions.
    #[arg(long)]
    owner_role: String,
    /// Restricted LOGIN role used by the Notary runtime.
    #[arg(long)]
    runtime_role: String,
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
        Some(Command::State {
            command: StateCommand::Install(install),
        }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            state_install(config_path, install).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::State {
            command: StateCommand::Doctor,
        }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            state_doctor(config_path).await?;
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

#[cfg(test)]
mod test_support;
