// SPDX-License-Identifier: Apache-2.0

//! The `messaging` binary entry point.

use registry_messaging::runtime::{command, operational_log_level, run};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    let level = match operational_log_level(std::env::var("MESSAGING_LOG").ok().as_deref()) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("messaging: {error}");
            std::process::exit(2);
        }
    };
    initialize_logging(level);

    let matches = command().get_matches();
    if let Err(error) = run(&matches).await {
        eprintln!("messaging: {error}");
        std::process::exit(1);
    }
}

/// JSON lines on standard output, from the Messaging crates only, so a
/// dependency's own logging never reaches the operational stream.
fn initialize_logging(level: LevelFilter) {
    let filter = Targets::new()
        .with_target("registry_messaging", level)
        .with_target("registry_messaging_core", level);
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
