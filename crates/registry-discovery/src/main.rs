// SPDX-License-Identifier: Apache-2.0
//! Registry Discovery process entry point.

use clap::Parser;
use registry_discovery::cli::Arguments;
use registry_discovery::{load_runtime, serve, LogLevel};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    let declared = match registry_platform_config::declared(arguments.posture.as_deref()) {
        Ok(declared) => declared,
        Err(error) => {
            eprintln!(
                "error[{}]: {}\nnext: {}",
                error.code(),
                error.message(),
                error.suggested_action()
            );
            std::process::exit(2);
        }
    };
    let level = load_runtime(&arguments.runtime_config, declared)
        .map(|(_, runtime)| match runtime.config.log_level {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
        })
        .unwrap_or(LevelFilter::INFO);
    let filter = Targets::new()
        .with_target("registry_discovery", level)
        .with_target("registry_platform_config::posture", LevelFilter::INFO);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false),
        )
        .init();
    if let Err(error) = serve(&arguments.runtime_config, declared).await {
        // The JSON log goes to standard output; the operator also gets the
        // refusal, with each diagnostic's position and fix, on standard error.
        eprintln!("discovery: {error}");
        tracing::error!(target: "registry_discovery::startup", error = %error, "Discovery stopped");
        std::process::exit(1);
    }
}
