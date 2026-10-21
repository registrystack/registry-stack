// SPDX-License-Identifier: Apache-2.0

//! The `documents` binary entry point.

use registry_documents::runtime::{command, operational_log_level, run};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    let level = match operational_log_level(std::env::var("DOCUMENTS_LOG").ok().as_deref()) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("documents: {error}");
            std::process::exit(2);
        }
    };
    initialize_logging(level);

    let matches = command().get_matches();
    if let Err(error) = run(&matches).await {
        eprintln!("documents: {error}");
        std::process::exit(1);
    }
}

/// JSON lines on standard error, from the Document Store crates only, so a
/// dependency's own logging never reaches the operational stream.
fn initialize_logging(level: LevelFilter) {
    let filter = Targets::new()
        .with_target("registry_documents", level)
        .with_target("registry_documents_core", level);
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
