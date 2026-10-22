// SPDX-License-Identifier: Apache-2.0
//! Base Registry Engine process entry point.

use clap::Parser;
use registry_breg::cli::Arguments;
use registry_breg::runtime_config::load_runtime_config;
use registry_breg::startup::{
    map_runtime_config_error, operational_log_level, prepare_loaded, select_operational_log_level,
    serve, OperationalEvent, OperationalLogLevel,
};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    let environment_log_level = match std::env::var("BREG_LOG") {
        Ok(value) => match operational_log_level(Some(&value)) {
            Ok(_) => Some(value),
            Err(error) => {
                initialize_logging(OperationalLogLevel::Error);
                OperationalEvent::StoppedWithError(error).emit();
                std::process::exit(2);
            }
        },
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            initialize_logging(OperationalLogLevel::Error);
            OperationalEvent::StoppedWithError(registry_breg::startup::StartupError::Logging)
                .emit();
            std::process::exit(2);
        }
    };

    if !arguments.runtime_config.is_absolute() {
        initialize_logging_filter(
            select_operational_log_level(environment_log_level.as_deref(), "info")
                .expect("the environment log level was validated"),
        );
        OperationalEvent::Stopped.emit();
        std::process::exit(2);
    }
    let config = match load_runtime_config(&arguments.runtime_config) {
        Ok(config) => config,
        Err(error) => {
            initialize_logging_filter(
                select_operational_log_level(environment_log_level.as_deref(), "info")
                    .expect("the environment log level was validated"),
            );
            OperationalEvent::StartupBegan.emit();
            // The operator reads every reader diagnostic, with its position
            // and fix, on stderr; the operational log on stdout carries only
            // the closed refusal class.
            eprintln!("breg did not start: its runtime configuration was refused.");
            eprint!("{}", error.render_human(Some(&arguments.runtime_config)));
            OperationalEvent::StoppedWithError(map_runtime_config_error(error)).emit();
            std::process::exit(1);
        }
    };
    let level = select_operational_log_level(
        environment_log_level.as_deref(),
        config.log_level().as_str(),
    )
    .expect("the environment and runtime log levels were validated");
    initialize_logging_filter(level);
    OperationalEvent::StartupBegan.emit();
    let clients_unrestricted = config.authentication().oidc().admits_every_client();
    let prepared = match prepare_loaded(config).await {
        Ok(prepared) => prepared,
        Err(error) => {
            OperationalEvent::StoppedWithError(error).emit();
            std::process::exit(1);
        }
    };
    OperationalEvent::RoleMode(prepared.role_mode()).emit();
    if clients_unrestricted {
        OperationalEvent::ClientsUnrestricted.emit();
    }
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
