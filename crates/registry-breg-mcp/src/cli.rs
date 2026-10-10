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
    /// Gateway runtime file. `serve` requires an absolute path; `check` also
    /// accepts a relative one.
    #[arg(long = "runtime-config", value_name = "FILE")]
    pub runtime_config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check the runtime file offline, reading no secret and opening no socket.
    ///
    /// The check reads the runtime file as `serve` does, with no secret
    /// material, network call, audit file, or listener. It does not prove that
    /// a secret the file names resolves or that the audit directory can be
    /// opened: `serve` proves both when it starts.
    Check(CheckArgs),
    /// Serve the gateway until it is terminated.
    Serve,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Emit the selected command's report in this format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,
    /// Fill `${NAME}` expressions in the runtime file from the process
    /// environment and check the values they produce. Without it, each
    /// expression is checked by syntax and position only.
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
