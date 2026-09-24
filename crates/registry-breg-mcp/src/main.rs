// SPDX-License-Identifier: Apache-2.0

//! The `breg-mcp` binary.

use std::process::ExitCode;

use clap::Parser;
use registry_breg_mcp::{
    cli::{Cli, Command},
    config::RuntimeConfig,
    runtime,
};

/// The environment variable holding the log filter directives.
const LOG_FILTER_VARIABLE: &str = "BREG_MCP_LOG";

fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env(LOG_FILTER_VARIABLE)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures name the failing field and stage, never the
            // resolved secret or the file contents that produced them.
            tracing::error!(target: "registry_breg_mcp", "{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let path = cli
        .runtime_config
        .ok_or_else(|| "--runtime-config is required".to_owned())?;
    let config = RuntimeConfig::load(&path)
        .map_err(|error| format!("the runtime configuration could not be loaded: {error}"))?;
    match cli.command {
        Command::Check => {
            runtime::check(&config)
                .map_err(|error| format!("the configuration cannot be served: {error}"))?;
            tracing::info!(target: "registry_breg_mcp", "configuration is valid");
            Ok(())
        }
        Command::Serve => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("the async runtime could not start: {error}"))?;
            runtime
                .block_on(runtime::serve(&config, shutdown_signal()))
                .map_err(|error| format!("the gateway could not serve: {error}"))
        }
    }
}

async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(target: "registry_breg_mcp", %error, "the interrupt signal cannot be observed");
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(error) => {
                tracing::error!(target: "registry_breg_mcp", %error, "the terminate signal cannot be observed");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!(target: "registry_breg_mcp", "shutting down");
}
