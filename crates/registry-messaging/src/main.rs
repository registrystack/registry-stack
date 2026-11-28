// SPDX-License-Identifier: Apache-2.0

//! The `messaging` binary entry point.

use registry_messaging::dispatch::Transports;
use registry_messaging::runtime::{command, operational_log_level, run};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    // Help and version answer without requiring valid operational settings.
    let matches = command().get_matches();
    if registry_platform_config::has_repeated_posture_flag() {
        eprintln!("messaging: [platform.posture.conflict] Declare --posture only once.");
        std::process::exit(2);
    }
    let flag = matches.get_one::<String>("posture").map(String::as_str);
    let posture = match registry_platform_config::declared(flag) {
        Ok(posture) => posture,
        Err(error) => {
            eprintln!(
                "messaging: {}: {}\n  next: {}",
                error.code(),
                error.message(),
                error.suggested_action()
            );
            std::process::exit(2);
        }
    };
    let level = match operational_log_level(std::env::var("MESSAGING_LOG").ok().as_deref()) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("messaging: {error}");
            std::process::exit(2);
        }
    };
    initialize_logging(level);

    if let Err(error) = run(&matches, posture, Transports::new()).await {
        if let registry_messaging::runtime::RuntimeError::Activation(
            registry_messaging::activation::ActivationError::PostureMismatch { message, action },
        ) = error
        {
            eprintln!(
                "messaging: {}: {message}\n  next: {action}",
                registry_messaging::activation::POSTURE_MISMATCH
            );
        } else {
            eprintln!("messaging: {error}");
        }
        std::process::exit(1);
    }
}

/// JSON lines on standard error, from the Messaging crates only, so a
/// dependency's own logging never reaches the operational stream and a
/// `stdout` audit destination carries audit entries alone.
fn initialize_logging(level: LevelFilter) {
    let filter = Targets::new()
        .with_target("registry_messaging", level)
        .with_target("registry_messaging_core", level)
        .with_target("registry_platform_config::posture", level);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(std::io::stderr),
        )
        .init();
}
