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
        /// Wallet-delivery deployment configuration file.
        #[arg(long, env = "EVIDENCE_OID4VCI_CONFIG")]
        config: PathBuf,
    },
    /// Validate the deployment and print its derived protocol metadata.
    Inspect {
        /// Wallet-delivery deployment configuration file.
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
        /// Wallet-delivery deployment configuration file.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_config_option_has_public_help() {
        let command = command();
        for name in ["check", "inspect", "serve"] {
            let subcommand = command.find_subcommand(name).expect("public subcommand");
            let config = subcommand
                .get_arguments()
                .find(|argument| argument.get_id() == "config")
                .expect("config option");
            assert!(
                config
                    .get_long_help()
                    .or_else(|| config.get_help())
                    .is_some_and(|help| !help.to_string().trim().is_empty()),
                "{name} --config lacks public help"
            );
        }
    }
}
