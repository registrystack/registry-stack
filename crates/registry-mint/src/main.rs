//! The `mint` binary.
//!
//! Two subcommands: `check` validates a deployment without opening a socket,
//! and `serve` runs the token endpoint. `SIGHUP` reloads the client registry in
//! place so onboarding a caller never restarts the service.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::{Parser, Subcommand};
use registry_mint::{
    config::MintConfig,
    server::{serve, MintService},
};

#[derive(Debug, Parser)]
#[command(name = "mint", about = "Registry Stack token issuer", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load the configuration, signing key, and client registry, then exit.
    Check {
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
    },
    /// Serve the token endpoint until terminated.
    Serve {
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures name the failing stage, never the key material
            // or the file contents that produced them.
            tracing::error!(target: "registry_mint", "{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Check { config } => {
            let service = load(&config)?;
            tracing::info!(
                target: "registry_mint",
                issuer = service.issuer(),
                clients = service.client_count(),
                "configuration is valid"
            );
            Ok(())
        }
        Command::Serve { config } => {
            let service = Arc::new(load(&config)?);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("the async runtime could not start: {error}"))?;
            runtime.block_on(async move {
                let reloads = Arc::clone(&service);
                tokio::spawn(async move { reload_on_hangup(reloads).await });
                serve(service, shutdown_signal())
                    .await
                    .map_err(|error| format!("the listener failed: {error}"))
            })
        }
    }
}

fn load(config: &Path) -> Result<MintService, String> {
    let config = MintConfig::load(config)
        .map_err(|error| format!("the configuration could not be loaded: {error}"))?;
    MintService::load(config).map_err(|error| format!("the service could not start: {error}"))
}

/// Reload the client registry on every `SIGHUP`, keeping the previous registry
/// when the new one does not load.
async fn reload_on_hangup(service: Arc<MintService>) {
    let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(hangup) => hangup,
        Err(error) => {
            tracing::error!(target: "registry_mint", "the hangup handler could not be installed: {error}");
            return;
        }
    };
    while hangup.recv().await.is_some() {
        match service.reload_clients() {
            Ok(clients) => {
                tracing::info!(target: "registry_mint", clients, "client registry reloaded");
            }
            Err(error) => {
                tracing::error!(
                    target: "registry_mint",
                    "the client registry was not reloaded and the previous one is still in use: {error}"
                );
            }
        }
    }
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
