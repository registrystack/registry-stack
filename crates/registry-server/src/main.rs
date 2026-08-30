// SPDX-License-Identifier: Apache-2.0
//! Registry Server process entry point.

use std::path::PathBuf;

use clap::Parser;
use registry_server::startup::{
    operational_log_level, prepare, serve, OperationalEvent, OperationalLogLevel,
};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

#[derive(Debug, Parser)]
#[command(
    name = "registry-server",
    about = "Serve one verified Registry Server package",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
struct Arguments {
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    let level = match operational_log_level(std::env::var("REGISTRY_SERVER_LOG").ok().as_deref()) {
        Ok(level) => level,
        Err(error) => {
            initialize_logging(OperationalLogLevel::Error);
            OperationalEvent::StoppedWithError(error).emit();
            std::process::exit(2);
        }
    };
    initialize_logging_filter(level);

    if !arguments.config.is_absolute() {
        OperationalEvent::Stopped.emit();
        std::process::exit(2);
    }
    OperationalEvent::StartupBegan.emit();
    let prepared = match prepare(&arguments.config).await {
        Ok(prepared) => prepared,
        Err(error) => {
            OperationalEvent::StoppedWithError(error).emit();
            std::process::exit(1);
        }
    };
    if let Err(error) = serve(prepared).await {
        OperationalEvent::StoppedWithError(error).emit();
        std::process::exit(1);
    }
}

fn initialize_logging(level: OperationalLogLevel) {
    let filter = match level {
        OperationalLogLevel::Info => tracing_subscriber::filter::LevelFilter::INFO,
        OperationalLogLevel::Warn => tracing_subscriber::filter::LevelFilter::WARN,
        OperationalLogLevel::Error => tracing_subscriber::filter::LevelFilter::ERROR,
    };
    initialize_logging_filter(filter);
}

fn initialize_logging_filter(level: tracing_subscriber::filter::LevelFilter) {
    let filter = Targets::new().with_target("registry_server", level);
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
}
