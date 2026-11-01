// SPDX-License-Identifier: Apache-2.0

//! The `adapter` binary entry point.

use std::io::Write as _;

use clap::Parser;
use registry_adapter::cli::{Cli, Command};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

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
    let result = match cli.command {
        Command::Serve {
            runtime_config,
            project,
            profile,
            pack,
        } => registry_adapter::serve::run(
            &project,
            profile.as_deref(),
            pack.as_deref(),
            &runtime_config,
        )
        .await
        .map_err(|error| error.to_string()),
        Command::EffectiveContract {
            runtime_config,
            project,
            profile,
            pack,
        } => export_effective_contract(
            &project,
            profile.as_deref(),
            pack.as_deref(),
            &runtime_config,
        ),
    };
    if let Err(error) = result {
        eprintln!("adapter: {error}");
        std::process::exit(1);
    }
}

fn export_effective_contract(
    project: &std::path::Path,
    profile: Option<&std::path::Path>,
    pack: Option<&std::path::Path>,
    runtime_config: &std::path::Path,
) -> Result<(), String> {
    let loaded = registry_adapter::engine::load::load(project, profile, pack, runtime_config)
        .map_err(|error| error.to_string())?;
    let document =
        registry_adapter::engine::effective_contract::EffectiveContract::from_loaded(&loaded)
            .and_then(|contract| contract.to_pretty_json())
            .map_err(|error| error.to_string())?;
    std::io::stdout()
        .write_all(document.as_bytes())
        .map_err(|error| format!("the effective contract could not be written: {error}"))
}
