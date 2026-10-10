// SPDX-License-Identifier: Apache-2.0
//! Registry Discovery process entry point.

use std::path::PathBuf;

use clap::Parser;
use registry_discovery::{load_runtime, serve, LogLevel};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[derive(Debug, Parser)]
#[command(
    name = "discovery",
    about = "Serve one immutable Registry Discovery index",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
struct Arguments {
    /// Absolute path of the runtime file naming the listener, index, and limits
    #[arg(long = "runtime-config", value_name = "FILE")]
    runtime_config: PathBuf,
}

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    let level = load_runtime(&arguments.runtime_config)
        .map(|(_, runtime)| match runtime.log_level {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
        })
        .unwrap_or(LevelFilter::INFO);
    let filter = Targets::new().with_target("registry_discovery", level);
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
    if let Err(error) = serve(&arguments.runtime_config).await {
        // The JSON log goes to standard output; the operator also gets the
        // refusal, with each diagnostic's position and fix, on standard error.
        eprintln!("discovery: {error}");
        tracing::error!(target: "registry_discovery::startup", error = %error, "Discovery stopped");
        std::process::exit(1);
    }
}
