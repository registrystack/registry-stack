// SPDX-License-Identifier: Apache-2.0

//! The `breg-mcp` command line.

use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::check::OutputFormat;

/// Serve one citizen-facing MCP endpoint over a Base Registry Engine.
#[derive(Debug, Parser)]
#[command(
    name = "breg-mcp",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Serve a citizen-facing MCP gateway over a Base Registry Engine"
)]
pub struct Cli {
    /// Absolute path to the gateway runtime configuration document.
    #[arg(long = "runtime-config", value_name = "FILE")]
    pub runtime_config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check the runtime configuration offline, reading no secret and opening no socket.
    Check(CheckArgs),
    /// Serve the gateway until it is terminated.
    Serve,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// How to write the findings.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    /// Refuse warnings as well as errors (exit 1).
    #[arg(long)]
    pub deny_warnings: bool,
    /// Substitute `${NAME}` expressions from this environment and check every
    /// value. Without it, each expression is checked by syntax and position
    /// only.
    #[arg(long)]
    pub environment: bool,
}

/// The complete clap command tree, built so help and the CLI reference can
/// render it.
#[must_use]
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}
