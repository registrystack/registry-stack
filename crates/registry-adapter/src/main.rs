// SPDX-License-Identifier: Apache-2.0

//! The `adapter` binary entry point.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[derive(Parser)]
#[command(name = "adapter", about = "The Registry Adapter runtime")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the governed facade.
    Serve {
        /// The operator runtime config.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        runtime_config: PathBuf,
        /// The directory holding project.yaml, profile.yaml, pack.yaml and scripts/.
        #[arg(long, value_name = "DIRECTORY")]
        project: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(Targets::new().with_target("registry_adapter", LevelFilter::INFO))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(std::io::stderr),
        )
        .init();
    let Command::Serve {
        runtime_config,
        project,
    } = cli.command;
    if let Err(error) = registry_adapter::serve::run(&project, &runtime_config).await {
        eprintln!("adapter: {error}");
        std::process::exit(1);
    }
}
