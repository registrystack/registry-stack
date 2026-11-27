// SPDX-License-Identifier: Apache-2.0
//! The `discovery` command line, shared by the process entry point and the
//! generated CLI reference.

use std::path::PathBuf;

use clap::{CommandFactory, Parser};

/// Arguments of the `discovery` process.
#[derive(Debug, Parser)]
#[command(
    name = "discovery",
    about = "Serve one immutable Registry Discovery index",
    version = crate::build_info::DISPLAY_VERSION
)]
pub struct Arguments {
    /// Runtime configuration file.
    #[arg(long = "runtime-config", value_name = "ABSOLUTE_FILE")]
    pub runtime_config: PathBuf,
}

/// The clap command tree, for the generated CLI reference.
#[must_use]
pub fn command() -> clap::Command {
    Arguments::command()
}
