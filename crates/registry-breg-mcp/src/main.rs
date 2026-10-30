// SPDX-License-Identifier: Apache-2.0

//! The `breg-mcp` binary.

use std::process::ExitCode;

use clap::Parser;
use registry_breg_mcp::{
    check,
    cli::{Cli, Command},
    config::{LogLevel, RuntimeConfig},
    runtime,
};
use tracing::Level;
use tracing_subscriber::{filter::Targets, prelude::*};

/// The environment variable holding the operational log level.
const LOG_VARIABLE: &str = "BREG_MCP_LOG";

/// The operational log level. The vocabulary is closed so a typo cannot
/// silently turn logging off or turn a dependency's logging on.
fn operational_log_level(
    value: Result<String, std::env::VarError>,
    configured: LogLevel,
) -> Result<Level, String> {
    match value {
        Err(std::env::VarError::NotPresent) => Ok(match configured {
            LogLevel::Error => Level::ERROR,
            LogLevel::Warn => Level::WARN,
            LogLevel::Info => Level::INFO,
        }),
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

fn operational_targets(level: Level) -> Targets {
    Targets::new()
        .with_target("registry_breg_mcp", level)
        .with_target("registry_mcp_edge", level)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // The offline check writes its own report and reads no log setting.
    if let Command::Check(arguments) = &cli.command {
        let request = check::CheckRequest {
            runtime: &cli.runtime_config,
            environment: arguments.environment,
            format: arguments.format,
            deny_warnings: arguments.deny_warnings,
        };
        return ExitCode::from(check::run(
            &request,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ));
    }

    let environment_level = match std::env::var(LOG_VARIABLE) {
        Err(std::env::VarError::NotPresent) => None,
        value => match operational_log_level(value, LogLevel::Info) {
            Ok(level) => Some(level),
            Err(error) => {
                eprintln!("breg-mcp: {error}");
                return ExitCode::from(2);
            }
        },
    };

    // A refused runtime file is reported in the shared human shape on
    // standard error (CFG-DIAG-2), naming members and never their values.
    let config = match RuntimeConfig::load(&cli.runtime_config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("breg-mcp: {error}");
            return ExitCode::FAILURE;
        }
    };
    let level = environment_level.unwrap_or_else(|| {
        operational_log_level(Err(std::env::VarError::NotPresent), config.log_level)
            .expect("the runtime log level was validated")
    });
    // JSON lines on standard output, from the BReg facade and its shared MCP
    // edge only. Dependency targets remain disabled.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false),
        )
        .with(operational_targets(level))
        .init();

    match serve(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures name the failing field and stage, never the
            // resolved secret or the file contents that produced them.
            tracing::error!(target: "registry_breg_mcp", "{message}");
            ExitCode::FAILURE
        }
    }
}

fn serve(config: &RuntimeConfig) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the async runtime could not start: {error}"))?;
    runtime
        .block_on(runtime::serve(config, shutdown_signal()))
        .map_err(|error| format!("the gateway could not serve: {error}"))
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
        use registry_breg_mcp::config::LogLevel;

        assert_eq!(
            operational_log_level(Err(std::env::VarError::NotPresent), LogLevel::Info),
            Ok(Level::INFO)
        );
        assert_eq!(
            operational_log_level(Err(std::env::VarError::NotPresent), LogLevel::Warn),
            Ok(Level::WARN)
        );
        assert_eq!(
            operational_log_level(Ok("error".to_owned()), LogLevel::Warn),
            Ok(Level::ERROR)
        );
        for (value, level) in [
            ("error", Level::ERROR),
            ("warn", Level::WARN),
            ("info", Level::INFO),
        ] {
            assert_eq!(
                operational_log_level(Ok(value.to_owned()), LogLevel::Info),
                Ok(level)
            );
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
                operational_log_level(Ok(refused.to_owned()), LogLevel::Info),
                Err("BREG_MCP_LOG must be one of error, warn, or info".to_owned()),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn operational_logs_include_the_facade_and_shared_edge_only() {
        let targets = operational_targets(Level::INFO);
        assert!(targets.would_enable("registry_breg_mcp", &Level::INFO));
        assert!(targets.would_enable("registry_mcp_edge::core", &Level::INFO));
        assert!(!targets.would_enable("registry_mcp_edge::core", &Level::DEBUG));
        assert!(!targets.would_enable("reqwest", &Level::ERROR));
    }
}
