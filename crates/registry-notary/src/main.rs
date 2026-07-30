// SPDX-License-Identifier: Apache-2.0
//! Registry Notary process entrypoint.

mod boot;
mod commands;
mod config_loader;
mod doctor;
mod env_file;
mod explain_config;
mod logging;
mod product_action;
mod serve;

use boot::*;
use commands::*;
use config_loader::*;
use doctor::*;
use env_file::*;
use explain_config::*;
use logging::*;
use product_action::*;

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
    EvidenceIssuerRegistry, NotaryActivationCode, NotaryActivationFailure, StandaloneServerError,
};
use registry_platform_config::{
    expand_config_env_vars, reject_deprecated_config_fields, verify_config_bundle,
    ConfigBundleError, VerifiedConfigBundle,
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, PublicJwk};
use registry_platform_ops::{
    antirollback_key_from_verified_bundle, audit_shipping_target, bundle_verify_rejection_code,
    evaluate_ack_health, load_unsigned_break_glass_or_pin,
    persist_bundle_acceptance as persist_config_bundle_acceptance,
    posture_safe_runtime_config_hash, resolve_bundle_state_action, AuditSinkKind,
    BundleStateAction, BundleStateRequest, BundleVerificationCode, BundleVerificationFailure,
    ConfigBootError, ConfigOverrideMode, ConfigProvenance, ConfigSource, PendingBundleAcceptance,
    UnsignedConfigSelection,
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
    /// Signed Config Bundle directory used for direct server startup.
    #[arg(
        long,
        requires_all = ["anchor_path", "state_path"],
        conflicts_with = "config"
    )]
    bundle_dir: Option<PathBuf>,
    /// Trust anchor JSON path used for direct signed-bundle startup.
    #[arg(
        long,
        requires_all = ["bundle_dir", "state_path"],
        conflicts_with = "config"
    )]
    anchor_path: Option<PathBuf>,
    /// Anti-rollback state JSON path used for direct signed-bundle startup.
    #[arg(
        long,
        requires_all = ["bundle_dir", "anchor_path"],
        conflicts_with = "config"
    )]
    state_path: Option<PathBuf>,
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
    /// Run one closed, release-mapped product action.
    ProductAction {
        #[command(subcommand)]
        action: ProductAction,
    },
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
    /// Inspect or recover the retained Notary audit chain.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
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
    /// Print the complete Draft 2020-12 standalone configuration schema.
    Schema,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Verify a Registry Config Bundle directory against local trust and state.
    VerifyBundle(ConfigVerifyBundleArgs),
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Quarantine an inconsistent file-backed chain and start a break segment.
    Quarantine(AuditQuarantineArgs),
}

#[derive(Debug, Clone, ClapArgs)]
struct AuditQuarantineArgs {
    /// Operator reason recorded in the tamper-evident chain-break event.
    #[arg(long)]
    reason: String,
    /// Optional operator identity recorded in the chain-break event.
    #[arg(long)]
    operator: Option<String>,
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
    let args = Args::parse();
    let server_startup =
        args.command.is_none() || matches!(&args.command, Some(Command::ProductAction { .. }));
    match run(args).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!(
                "ERROR {}",
                top_level_error_message(err.as_ref(), server_startup)
            );
            ExitCode::FAILURE
        }
    }
}

// Process diagnostics and governed audit records have different publication
// boundaries. Diagnostics must be value-free. A configured stdout audit sink is
// protected operator evidence, so accepted bundle identities, signer ids, and
// integrity hashes intentionally remain in `config.bundle_accepted` records.
fn top_level_error_message(
    error: &(dyn std::error::Error + 'static),
    server_startup: bool,
) -> String {
    if !server_startup {
        return error.to_string();
    }
    if let Some(failure) = error.downcast_ref::<BundleVerificationFailure>() {
        return failure.to_string();
    }
    error
        .downcast_ref::<NotaryActivationFailure>()
        .copied()
        .unwrap_or_else(|| NotaryActivationCode::RUNTIME_ACTIVATION_FAILED.into())
        .to_string()
}

async fn run(args: Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if let Some(Command::ProductAction { action }) = args.command.as_ref() {
        ensure_closed_product_action_arguments(&args)?;
        run_product_action(*action).await?;
        return Ok(ExitCode::SUCCESS);
    }
    let server_startup = args.command.is_none();
    let server_config_input = if server_startup {
        Some(server_config_input(&args).map_err(value_free_configuration_failure)?)
    } else {
        if args.bundle_dir.is_some() || args.anchor_path.is_some() || args.state_path.is_some() {
            return Err(
                "--bundle-dir, --anchor-path, and --state-path are server-startup-only arguments"
                    .into(),
            );
        }
        None
    };
    let doctor_command = matches!(
        &args.command,
        Some(Command::Doctor { .. })
            | Some(Command::State {
                command: StateCommand::Doctor,
            })
    );
    let env_report = match load_env_file_arg(args.env_file.as_deref(), args.env_file_override) {
        Ok(report) => report,
        Err(error) if server_startup || doctor_command => {
            return Err(Box::new(value_free_configuration_failure(error)));
        }
        Err(error) => return Err(error),
    };
    if matches!(
        server_config_input.as_ref(),
        Some(ServerConfigInput::SignedBundle { .. })
    ) && env_report.contains("REGISTRY_NOTARY_CONFIG")
    {
        return Err(Box::new(value_free_configuration_failure(
            "REGISTRY_NOTARY_CONFIG cannot be supplied by --env-file for direct bundle startup",
        )));
    }
    match args.command {
        None => {
            run_server(
                server_config_input.expect("server startup input was resolved"),
                args.bind,
                args.initialize_state,
            )
            .await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::ProductAction { .. }) => {
            unreachable!("product actions return before legacy input resolution")
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
        Some(Command::Audit {
            command: AuditCommand::Quarantine(quarantine_args),
        }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            audit_quarantine(config_path, quarantine_args)?;
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
            print!("{}", registry_notary_core::config::schema::document_json());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn server_config_input(args: &Args) -> Result<ServerConfigInput, &'static str> {
    match (
        args.config.as_ref(),
        args.bundle_dir.as_ref(),
        args.anchor_path.as_ref(),
        args.state_path.as_ref(),
    ) {
        (Some(config_path), None, None, None) => {
            Ok(ServerConfigInput::LocalFile(config_path.clone()))
        }
        (None, Some(bundle_dir), Some(anchor_path), Some(state_path)) => {
            Ok(ServerConfigInput::SignedBundle {
                bundle_dir: bundle_dir.clone(),
                anchor_path: anchor_path.clone(),
                state_path: state_path.clone(),
            })
        }
        (None, None, None, None) => {
            Err("--config or the complete signed-bundle startup arguments are required")
        }
        _ => Err("local config and signed-bundle startup arguments cannot be combined"),
    }
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod operator_boundary_tests {
    use super::*;

    #[test]
    fn accepted_bundle_audit_keeps_governed_identity_at_the_protected_boundary() {
        const CONFIG_HASH: &str =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        const PREVIOUS_HASH: &str =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let acceptance = PendingBundleAcceptance {
            state_path: PathBuf::from(
                "/Users/SENTINEL_USER/SENTINEL_COUNTRY/SENTINEL_SECRET_STATE.json",
            ),
            key: registry_platform_ops::AntiRollbackKey {
                acceptance_identity: registry_platform_config::ProductAcceptanceIdentityV1 {
                    trust_domain: registry_platform_config::ProductTrustDomainV1::Governed,
                    project: "governed-project".to_string(),
                    environment: "SENTINEL_COUNTRY".to_string(),
                    lane: registry_platform_config::ProductAcceptanceLaneV1::Notary,
                    product: registry_platform_config::ProductAcceptanceProductV1::RegistryNotary,
                    stream: "governed-stream".to_string(),
                    instance: "SENTINEL_PARSER_INSTANCE".to_string(),
                },
            },
            accepted_anchor: registry_platform_ops::AcceptedAnchorPinV1 {
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                version: 1,
                threshold: 1,
                enabled_signers: vec!["governed-signer-kid".to_string()],
            },
            source: ConfigSource::SignedBundleFile,
            bundle_id: Some("governed-bundle-42".to_string()),
            bundle_manifest_hash: Some(
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_string(),
            ),
            sequence: Some(42),
            config_hash: CONFIG_HASH.to_string(),
            previous_config_hash: Some(PREVIOUS_HASH.to_string()),
            previous_hash_matched: Some(true),
            signer_kids: vec!["governed-signer-kid".to_string()],
            break_glass: false,
            state_action: BundleStateAction::Accept,
            override_pin: None,
            override_path: None,
        };

        let rendered =
            serde_json::to_string(&bundle_acceptance_audit(&acceptance)).expect("audit serializes");

        for governed_value in [
            "governed-bundle-42",
            "governed-signer-kid",
            CONFIG_HASH,
            PREVIOUS_HASH,
        ] {
            assert!(
                rendered.contains(governed_value),
                "accepted audit lost governed identity evidence {governed_value:?}: {rendered}"
            );
        }
        for raw_value in [
            "SENTINEL_USER",
            "SENTINEL_COUNTRY",
            "SENTINEL_SECRET",
            "SENTINEL_PARSER",
            acceptance.state_path.to_str().expect("test path is UTF-8"),
        ] {
            assert!(
                !rendered.contains(raw_value),
                "accepted audit crossed its protected boundary with raw value {raw_value:?}: {rendered}"
            );
        }
    }
}
