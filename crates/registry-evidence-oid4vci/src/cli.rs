//! Evidence wallet-delivery command-line contract.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "evidence-oid4vci",
    about = "Registry Stack wallet delivery front end for Evidence credentials",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Load and validate the configuration and the client key, then exit.
    Check {
        #[arg(long, env = "EVIDENCE_OID4VCI_CONFIG")]
        config: PathBuf,
    },
    /// Validate the deployment and print its derived protocol metadata.
    Inspect {
        #[arg(long, env = "EVIDENCE_OID4VCI_CONFIG")]
        config: PathBuf,
    },
    /// Render the deterministic OpenAPI 3.1 contract, then exit.
    Openapi {
        /// Write to a file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Serve the delivery endpoints until terminated.
    Serve {
        #[arg(long, env = "EVIDENCE_OID4VCI_CONFIG")]
        config: PathBuf,
    },
}

/// Return the complete command tree without running wallet delivery.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}
