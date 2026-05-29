// SPDX-License-Identifier: Apache-2.0
//! Registry Notary process entrypoint.

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::Request;
use clap::{Parser, Subcommand};
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::{openapi_document, standalone_router};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the standalone Registry Notary")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// YAML config path.
    #[arg(short, long, env = "REGISTRY_NOTARY_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the Registry Notary OpenAPI document as JSON.
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
            EnvFilter::new("info,registry_notary_server=debug,registry_notary_bin=debug")
        }))
        .init();

    let raw = tokio::fs::read_to_string(&config_path).await?;
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(&raw)?;
    config.validate()?;

    let bind = config.server.bind;
    let app = standalone_router(config)?.layer(TraceLayer::new_for_http().make_span_with(
        |request: &Request<Body>| {
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
        },
    ));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    tracing::info!(%local_addr, "registry notary listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
