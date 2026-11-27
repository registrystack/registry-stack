// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;

use registry_session::command;
use registry_session::config::{LogLevel, RuntimeConfig};
use registry_session::gateway::{self, Mode};
use registry_session::offline::{self, CheckRequest, OutputFormat};
use registry_session::runtime::{serve, Service};
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

const LOG_VARIABLE: &str = "REGISTRY_SESSION_LOG";

/// The operational log level. The vocabulary is closed so a typo cannot
/// silently turn logging off or on.
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

#[tokio::main]
async fn main() -> ExitCode {
    let matches = command().get_matches();
    let given = matches.get_one::<PathBuf>("runtime-config");
    let verify_only = matches
        .subcommand_matches("gateway")
        .and_then(|gateway| gateway.subcommand_matches("envoy"))
        .is_some_and(|envoy| envoy.contains_id("verify-assembled"));
    // Verifying an assembled file reads no runtime file.
    let none = PathBuf::new();
    let Some(path) = given.or(verify_only.then_some(&none)) else {
        eprintln!("registry-session: --runtime-config is required");
        return ExitCode::from(2);
    };

    // The offline check writes its own report and reads no log setting.
    if let Some(("check", arguments)) = matches.subcommand() {
        let request = CheckRequest {
            runtime: path,
            environment: arguments.get_flag("environment"),
            format: *arguments
                .get_one::<OutputFormat>("format")
                .expect("clap defaults --format"),
            deny_warnings: arguments.get_flag("deny-warnings"),
            identity_receipt: arguments
                .get_one::<PathBuf>("identity-receipt")
                .map(PathBuf::as_path),
        };
        return ExitCode::from(offline::run(
            &request,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ));
    }

    if let Some(("gateway", gateway_arguments)) = matches.subcommand() {
        let Some(("envoy", arguments)) = gateway_arguments.subcommand() else {
            return ExitCode::from(2);
        };
        if let Some(assembled) = arguments.get_one::<PathBuf>("verify-assembled") {
            return match gateway::verify_assembled(assembled) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("registry-session: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        let result = if let Some(assembled) = arguments.get_one::<PathBuf>("verify-assembled") {
            gateway::verify_assembled(assembled)
        } else {
            let mode = match (
                arguments.get_one::<PathBuf>("out"),
                arguments.get_one::<PathBuf>("check"),
            ) {
                (Some(out), _) => Mode::Write(out),
                (None, Some(check)) => Mode::Check(check),
                (None, None) => return ExitCode::from(2),
            };
            gateway::run_envoy(path, mode)
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("registry-session: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let environment_level = match std::env::var(LOG_VARIABLE) {
        Err(std::env::VarError::NotPresent) => None,
        value => match operational_log_level(value, LogLevel::Info) {
            Ok(level) => Some(level),
            Err(error) => {
                eprintln!("registry-session: {error}");
                return ExitCode::from(2);
            }
        },
    };

    // A refused runtime file is reported in the shared human shape on standard
    // error (CFG-DIAG-2), naming members and never their values.
    let config = match RuntimeConfig::load(path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("registry-session: {error}");
            return ExitCode::FAILURE;
        }
    };
    let level = environment_level.unwrap_or_else(|| {
        operational_log_level(Err(std::env::VarError::NotPresent), config.log_level)
            .expect("the runtime log level was validated")
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false),
        )
        .with(
            Targets::new()
                .with_target("registry_session", level)
                .with_target("registry_session_bin", level),
        )
        .init();

    match run_serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("registry-session: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_serve(config: RuntimeConfig) -> Result<(), String> {
    let public_bind = config.listener.bind.socket_addr();
    let check_bind = config.check_listener.socket_addr();
    let service = Service::build(config, None)
        .await
        .map_err(|error| error.to_string())?;
    let public = tokio::net::TcpListener::bind(public_bind)
        .await
        .map_err(|error| format!("could not listen on {public_bind}: {error}"))?;
    let check = tokio::net::TcpListener::bind(check_bind)
        .await
        .map_err(|error| format!("could not listen on {check_bind}: {error}"))?;
    tracing::info!(%public_bind, %check_bind, "the session service is listening");
    serve(public, check, service)
        .await
        .map_err(|error| format!("the session service stopped: {error}"))?;
    tracing::info!("the session service stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_is_well_formed() {
        command().debug_assert();
    }

    #[test]
    fn the_log_level_vocabulary_is_closed() {
        assert_eq!(
            operational_log_level(Err(std::env::VarError::NotPresent), LogLevel::Warn),
            Ok(Level::WARN)
        );
        assert_eq!(
            operational_log_level(Ok("error".to_owned()), LogLevel::Warn),
            Ok(Level::ERROR)
        );
        assert!(operational_log_level(Ok("debug".to_owned()), LogLevel::Info).is_err());
    }
}
