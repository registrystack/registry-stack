// SPDX-License-Identifier: Apache-2.0

//! The `breg-mcp` command line.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

/// Serve one citizen-facing MCP endpoint over a Base Registry Engine.
#[derive(Debug, Parser)]
#[command(
    name = "breg-mcp",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Serve a citizen-facing MCP gateway over a Base Registry Engine"
)]
pub struct Cli {
    /// Absolute path to the gateway runtime configuration document.
    #[arg(long = "runtime-config", value_name = "FILE", global = true)]
    pub runtime_config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate the runtime configuration and resolve its secrets without opening a socket.
    Check,
    /// Serve the gateway until it is terminated.
    Serve,
}

/// The complete clap command tree, built so help and the CLI reference can
/// render it.
#[must_use]
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}
