// SPDX-License-Identifier: Apache-2.0
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    initialize_logging();
    registry_coordinator::service::run().await
}

/// JSON lines on standard error at a fixed `info` level, from the Coordinator
/// crate only, so a dependency's own logging never reaches the operational
/// stream.
fn initialize_logging() {
    tracing_subscriber::registry()
        .with(Targets::new().with_target("registry_coordinator", LevelFilter::INFO))
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
