// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;

use registry_breg_review::check::{self, CheckRequest, OutputFormat};
use registry_breg_review::{command, router, serve, RuntimeConfig};
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

const LOG_VARIABLE: &str = "BREG_REVIEW_LOG";

/// The operational log level. The vocabulary is closed so a typo cannot
/// silently turn logging off or on.
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

#[tokio::main]
async fn main() -> ExitCode {
    let matches = command().get_matches();
    let path = matches
        .get_one::<PathBuf>("runtime-config")
        .expect("clap requires --runtime-config");

    // The offline check writes its own report and reads no log setting.
    if let Some(("check", arguments)) = matches.subcommand() {
        let request = CheckRequest {
            runtime: path,
            environment: arguments.get_flag("environment"),
            format: *arguments
                .get_one::<OutputFormat>("format")
                .expect("clap defaults --format"),
            deny_warnings: arguments.get_flag("deny-warnings"),
        };
        return ExitCode::from(check::run(
            &request,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ));
    }

    let level = match operational_log_level(std::env::var(LOG_VARIABLE)) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("breg-review: {error}");
            return ExitCode::from(2);
        }
    };
    // A refused runtime file is reported in the shared human shape on
    // standard error (CFG-DIAG-2), naming members and never their values.
    let config = match RuntimeConfig::load(path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("breg-review: {error}");
            return ExitCode::FAILURE;
        }
    };
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
                .with_target("breg_review", level)
                .with_target("registry_breg_review", level),
        )
        .init();

    // Startup refusals go to standard error, apart from the JSON operational
    // log on standard output, and name the failing field without its value.
    match run_serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("breg-review: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_serve(config: RuntimeConfig) -> Result<(), String> {
    let bind = config.listener.bind.socket_addr();
    let router = router(config).await.map_err(|error| error.to_string())?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| format!("could not listen on {bind}: {error}"))?;
    tracing::info!(%bind, "the review page is listening");
    serve(listener, router)
        .await
        .map_err(|error| format!("the review page stopped: {error}"))?;
    tracing::info!("the review page stopped");
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
            operational_log_level(Err(std::env::VarError::NotPresent)),
            Ok(Level::INFO)
        );
        assert_eq!(
            operational_log_level(Ok("warn".to_owned())),
            Ok(Level::WARN)
        );
        assert!(operational_log_level(Ok("debug".to_owned())).is_err());
        assert!(operational_log_level(Ok("trace".to_owned())).is_err());
    }
}
