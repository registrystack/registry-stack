// SPDX-License-Identifier: Apache-2.0
//! The Relay V2 `relay` process.

use std::process::ExitCode;

use clap::Parser;
use registry_relay_v2::cli::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    install_operational_logging();
    let result = match Cli::parse().command {
        Command::Check {
            runtime,
            require_audit_under,
        } => registry_relay_v2::startup::check(&runtime, require_audit_under.as_deref()).await,
        Command::Serve { runtime } => registry_relay_v2::startup::serve(&runtime).await,
        Command::Healthcheck { url } => registry_relay_v2::startup::healthcheck(&url).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(target: "registry_relay_v2", error = %error, "relay command failed");
            ExitCode::FAILURE
        }
    }
}

/// Install bounded structured operational logs on stderr. Relay-owned events
/// deliberately carry only fixed messages and value-free dimensions.
fn install_operational_logging() {
    let configured = std::env::var("RELAY_LOG").ok();
    let filter =
        tracing_subscriber::EnvFilter::new(operational_log_directive(configured.as_deref()));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(std::io::stderr)
        .init();
}

/// Accept only one closed level for Relay-owned targets. An arbitrary tracing
/// directive could enable dependency events containing URLs or headers.
fn operational_log_directive(configured: Option<&str>) -> &'static str {
    match configured {
        Some("off") => "registry_relay_v2=off",
        Some("error") => "registry_relay_v2=error",
        Some("warn") => "registry_relay_v2=warn",
        Some("debug") => "registry_relay_v2=debug",
        Some("trace") => "registry_relay_v2=trace",
        Some("info") | None => "registry_relay_v2=info",
        Some(_) => "registry_relay_v2=info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operational_log_filter_cannot_enable_dependency_targets() {
        assert_eq!(
            operational_log_directive(Some("trace,hyper=trace")),
            "registry_relay_v2=info"
        );
        assert_eq!(
            operational_log_directive(Some("registry_relay_v2=off,reqwest=trace")),
            "registry_relay_v2=info"
        );
        assert_eq!(
            operational_log_directive(Some("debug")),
            "registry_relay_v2=debug"
        );
    }
}
