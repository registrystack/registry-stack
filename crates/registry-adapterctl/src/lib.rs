// SPDX-License-Identifier: Apache-2.0

//! `adapterctl`, the Registry Stack Adapter authoring and operator tooling.
//!
//! This crate owns the `adapterctl` binary: the offline check over
//! authored artifacts, per-deployment compilation, fixture replay, and the
//! live verification of an installed adapter
//! (`products/adapter/CONCEPT.md` section 8.1). It reads the same
//! source-neutral model the runtime serves, so an artifact `adapterctl
//! check` accepts is one the runtime can interpret.

use clap::{CommandFactory, Parser};

/// The `adapterctl` command tree, exposed for reference tooling.
pub fn command() -> clap::Command {
    Cli::command()
}

#[derive(Debug, Parser)]
#[command(
    name = "adapterctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Stack Adapter authoring and operator tooling"
)]
struct Cli {}

/// Entry point behind the thin `main.rs`, so tests can run it in process.
pub fn main_entry() -> std::process::ExitCode {
    Cli::parse();
    std::process::ExitCode::SUCCESS
}
