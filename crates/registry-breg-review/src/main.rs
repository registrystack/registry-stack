// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

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
async fn main() {
    let matches = command().get_matches();
    let level = match operational_log_level(std::env::var(LOG_VARIABLE)) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("breg-review: {error}");
            std::process::exit(2);
        }
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(std::io::stderr),
        )
        .with(
            Targets::new()
                .with_target("breg_review", level)
                .with_target("registry_breg_review", level),
        )
        .init();

    let path = matches
        .get_one::<PathBuf>("runtime-config")
        .expect("clap requires --runtime-config");
    if let Err(error) = run(path).await {
        eprintln!("breg-review: {error}");
        std::process::exit(1);
    }
}

async fn run(path: &std::path::Path) -> Result<(), String> {
    let config =
        RuntimeConfig::load(path).map_err(|error| format!("{error} (at {})", error.path()))?;
    let bind = config.listener.bind;
    let router = router(config).await.map_err(|error| error.to_string())?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| format!("could not listen on {bind}: {error}"))?;
    tracing::info!(%bind, "the review page is listening");
    serve(listener, router)
        .await
        .map_err(|error| format!("the review page stopped: {error}"))
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
