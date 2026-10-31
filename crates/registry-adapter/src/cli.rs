// SPDX-License-Identifier: Apache-2.0

//! The canonical `adapter` command tree, shared by the runtime binary and
//! the generated Registry Stack CLI catalog.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "adapter", about = "The Registry Adapter runtime")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Serve the governed facade.
    Serve {
        /// Runtime configuration file.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        runtime_config: PathBuf,
        /// The directory holding project.yaml.
        #[arg(long, value_name = "DIRECTORY")]
        project: PathBuf,
        /// The profile file; defaults to profile.yaml beside the project.
        #[arg(long, value_name = "FILE")]
        profile: Option<PathBuf>,
        /// The pack file, whose scripts/ sit beside it; defaults to pack.yaml
        /// beside the project.
        #[arg(long, value_name = "FILE")]
        pack: Option<PathBuf>,
    },
    /// Export the loaded gateway contract without binding a listener.
    EffectiveContract {
        /// Runtime configuration file.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        runtime_config: PathBuf,
        /// The directory holding project.yaml.
        #[arg(long, value_name = "DIRECTORY")]
        project: PathBuf,
        /// The profile file; defaults to profile.yaml beside the project.
        #[arg(long, value_name = "FILE")]
        profile: Option<PathBuf>,
        /// The pack file, whose scripts/ sit beside it; defaults to pack.yaml
        /// beside the project.
        #[arg(long, value_name = "FILE")]
        pack: Option<PathBuf>,
    },
}

/// Return the same command tree the `adapter` binary parses.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}
