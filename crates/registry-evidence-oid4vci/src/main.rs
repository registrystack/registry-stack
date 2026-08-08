//! The `evidence-oid4vci` binary.
//!
//! Two subcommands. `check` loads and validates a deployment without opening a
//! socket, so an operator can validate an edited configuration on the host that
//! is already serving the old one. `serve` runs the delivery service until it is
//! terminated.

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use clap::{Parser, Subcommand};
use registry_evidence_oid4vci::{
    config::DeliveryConfig,
    service::{serve, DeliveryService},
};

#[derive(Debug, Parser)]
#[command(
    name = "evidence-oid4vci",
    about = "Registry Stack wallet delivery front end for Evidence credentials",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load and validate the configuration and the client key, then exit.
    Check {
        #[arg(long, env = "EVIDENCE_OID4VCI_CONFIG")]
        config: PathBuf,
    },
    /// Serve the delivery endpoints until terminated.
    Serve {
        #[arg(long, env = "EVIDENCE_OID4VCI_CONFIG")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures name the failing stage, never the key material
            // or the file contents that produced them.
            tracing::error!(target: "registry_evidence_oid4vci", "{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Check { config } => {
            let config = load_config(&config)?;
            DeliveryService::check(&config)
                .map_err(|error| format!("the configuration cannot be served: {error}"))?;
            tracing::info!(
                target: "registry_evidence_oid4vci",
                credential_issuer = config.credential_issuer,
                "configuration is valid"
            );
            Ok(())
        }
        Command::Serve { config } => {
            let config = load_config(&config)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("the async runtime could not start: {error}"))?;
            runtime.block_on(async move {
                let service = Arc::new(
                    DeliveryService::load(config)
                        .map_err(|error| format!("the service could not start: {error}"))?,
                );
                serve(service, shutdown_signal())
                    .await
                    .map_err(|error| format!("the listener failed: {error}"))
            })
        }
    }
}

fn load_config(path: &std::path::Path) -> Result<DeliveryConfig, String> {
    DeliveryConfig::load(path)
        .map_err(|error| format!("the configuration could not be loaded: {error}"))
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
