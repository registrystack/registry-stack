// SPDX-License-Identifier: Apache-2.0

//! The `breg-mcp` binary.

use std::process::ExitCode;

use clap::Parser;
use registry_breg_mcp::{
    cli::{Cli, Command},
    config::RuntimeConfig,
    runtime,
};
use tracing::Level;
use tracing_subscriber::{filter::Targets, prelude::*};

/// The environment variable holding the operational log level.
const LOG_VARIABLE: &str = "BREG_MCP_LOG";

/// The operational log level. The vocabulary is closed so a typo cannot
/// silently turn logging off or turn a dependency's logging on.
fn operational_log_level(value: Result<String, std::env::VarError>) -> Result<Level, String> {
    match value {
        Err(std::env::VarError::NotPresent) => Ok(Level::INFO),
        Ok(value) => match value.as_str() {
            "error" => Ok(Level::ERROR),
            "warn" => Ok(Level::WARN),
            "info" => Ok(Level::INFO),
            _ => Err(format!(
                "{LOG_VARIABLE} must be one of error, warn, or info"
            )),
        },
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{LOG_VARIABLE} must be one of error, warn, or info"
        )),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let level = match operational_log_level(std::env::var(LOG_VARIABLE)) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("breg-mcp: {error}");
            return ExitCode::from(2);
        }
    };
    // JSON lines on standard output, from this crate only.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false),
        )
        .with(Targets::new().with_target("registry_breg_mcp", level))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_level_vocabulary_is_closed() {
        assert_eq!(
            operational_log_level(Err(std::env::VarError::NotPresent)),
            Ok(Level::INFO)
        );
        for (value, level) in [
            ("error", Level::ERROR),
            ("warn", Level::WARN),
            ("info", Level::INFO),
        ] {
            assert_eq!(operational_log_level(Ok(value.to_owned())), Ok(level));
        }
        for refused in [
            "debug",
            "trace",
            "off",
            "Info",
            "",
            "registry_breg_mcp=info",
        ] {
            assert_eq!(
                operational_log_level(Ok(refused.to_owned())),
                Err("BREG_MCP_LOG must be one of error, warn, or info".to_owned()),
                "{refused:?}"
            );
        }
    }
}
