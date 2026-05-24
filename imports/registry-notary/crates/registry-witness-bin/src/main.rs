// SPDX-License-Identifier: Apache-2.0
//! Registry Witness process entrypoint.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use registry_witness_core::StandaloneRegistryWitnessConfig;
use registry_witness_server::{openapi_document, standalone_router};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the standalone Registry Witness")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// YAML config path.
    #[arg(short, long, env = "REGISTRY_WITNESS_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the Registry Witness OpenAPI document as JSON.
    Openapi,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if matches!(args.command, Some(Command::Openapi)) {
        println!("{}", openapi_document().to_pretty_json()?);
        return Ok(());
    }
    let config_path = args
        .config
        .ok_or("--config is required unless a subcommand is used")?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,registry_witness_server=debug,registry_witness_bin=debug")
        }))
        .init();

    let raw = tokio::fs::read_to_string(&config_path).await?;
    let config: StandaloneRegistryWitnessConfig = serde_norway::from_str(&raw)?;
    config.validate()?;

    let bind = config.server.bind;
    let app = standalone_router(config)?.layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    tracing::info!(%local_addr, "registry witness listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
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
