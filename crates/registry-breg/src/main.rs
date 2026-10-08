// SPDX-License-Identifier: Apache-2.0
//! Base Registry Engine process entry point.

use clap::Parser;
use registry_breg::cli::Arguments;
use registry_breg::runtime_config::load_runtime_config;
use registry_breg::startup::{
    map_runtime_config_error, operational_log_level, prepare_loaded, serve, OperationalEvent,
    OperationalLogLevel,
};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    let level = match operational_log_level(std::env::var("BREG_LOG").ok().as_deref()) {
        Ok(level) => level,
        Err(error) => {
            initialize_logging(OperationalLogLevel::Error);
            OperationalEvent::StoppedWithError(error).emit();
            std::process::exit(2);
        }
    };
    initialize_logging_filter(level);

    if !arguments.runtime_config.is_absolute() {
        OperationalEvent::Stopped.emit();
        std::process::exit(2);
    }
    OperationalEvent::StartupBegan.emit();
    let config = match load_runtime_config(&arguments.runtime_config) {
        Ok(config) => config,
        Err(error) => {
            // The operator reads every reader diagnostic, with its position
            // and fix, on stderr; the operational log on stdout carries only
            // the closed refusal class.
            eprintln!("breg did not start: its runtime configuration was refused.");
            eprint!("{}", error.render_human(Some(&arguments.runtime_config)));
            OperationalEvent::StoppedWithError(map_runtime_config_error(error)).emit();
            std::process::exit(1);
        }
    };
    let prepared = match prepare_loaded(config).await {
        Ok(prepared) => prepared,
        Err(error) => {
            OperationalEvent::StoppedWithError(error).emit();
            std::process::exit(1);
        }
    };
    OperationalEvent::RoleMode(prepared.role_mode()).emit();
    for advisory in prepared.postgres_advisories() {
        OperationalEvent::PostgresBaselineAdvisory(advisory.clone()).emit();
    }
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
    let filter = Targets::new().with_target("registry_breg", level);
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
