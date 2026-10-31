// SPDX-License-Identifier: Apache-2.0

//! The canonical `registry-mcp` command tree, shared by the runtime binary and
//! the generated Registry Stack CLI catalog.

use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

/// Serve explicitly configured native and adapter MCP capabilities.
#[derive(Debug, Parser)]
#[command(
    name = "registry-mcp",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Serve explicitly configured native and adapter MCP capabilities"
)]
pub struct Cli {
    /// Runtime configuration file.
    #[arg(long, value_name = "FILE")]
    pub runtime_config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check configuration offline, without credentials, sockets or audit writes.
    Check(CheckArgs),
    /// Serve the configured MCP gateway until it is terminated.
    Serve,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Emit the selected command's report in this format.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
    /// Fill environment expressions before checking their resulting values.
    #[arg(long)]
    pub environment: bool,
    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    Human,
    Json,
}

/// Return the same command tree the `registry-mcp` binary parses.
#[must_use]
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}
