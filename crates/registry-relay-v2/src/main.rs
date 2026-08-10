// SPDX-License-Identifier: Apache-2.0
//! The Relay V2 `relay` process.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

const DEFAULT_HEALTHCHECK_URL: &str = "http://127.0.0.1:8080/health";

#[derive(Debug, Parser)]
#[command(
    name = "relay",
    about = "Compiled read-only Registry Relay runtime",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify and activate one sealed Registry package, then serve it.
    Serve {
        /// Strict deployment binding for the sealed package and local resources.
        #[arg(long, env = "RELAY_RUNTIME")]
        runtime: PathBuf,
    },
    /// Probe an unauthenticated Relay liveness endpoint.
    Healthcheck {
        /// Complete HTTP(S) URL of the Relay `/health` endpoint.
        #[arg(
            long,
            env = "RELAY_HEALTHCHECK_URL",
            default_value = DEFAULT_HEALTHCHECK_URL
        )]
        url: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    install_operational_logging();
    let result = match Cli::parse().command {
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
    use std::ffi::OsStr;

    use clap::CommandFactory;

    use super::*;

    #[test]
    fn healthcheck_endpoint_has_a_safe_configurable_default() {
        let command = Cli::command();
        let healthcheck = command
            .find_subcommand("healthcheck")
            .expect("healthcheck subcommand exists");
        let url = healthcheck
            .get_arguments()
            .find(|argument| argument.get_id() == "url")
            .expect("healthcheck URL argument exists");
        assert_eq!(url.get_env(), Some(OsStr::new("RELAY_HEALTHCHECK_URL")));
        assert_eq!(
            url.get_default_values(),
            [OsStr::new(DEFAULT_HEALTHCHECK_URL)]
        );
    }

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
