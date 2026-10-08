//! Evidence wallet-delivery command-line contract.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

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
    /// Check the configuration offline, as `serve` reads it, then exit.
    ///
    /// Reads the one file and nothing else: no network, no socket, and no
    /// secret material. The client key is resolved, and its JWK parsed, when
    /// `serve` or `inspect` starts. Exits 0 when the file passes, 1 when it
    /// breaks a rule, 2 when the command line is invalid, and 3 when the file
    /// cannot be read.
    Check {
        /// Wallet-delivery deployment configuration file.
        #[arg(long, env = "EVIDENCE_OID4VCI_CONFIG")]
        config: PathBuf,
        /// Report for a person (`human`) or as one JSON document on standard
        /// output (`json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        /// Exit 1 when the check reports a warning.
        #[arg(long)]
        deny_warnings: bool,
        /// Substitute `${...}` expressions from this process's environment, as
        /// startup does, and check the values they fill. Without it an
        /// expression is checked by its syntax and position only.
        #[arg(long)]
        environment: bool,
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

/// Who a check report is rendered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    /// Position-first diagnostic lines and a summary for a person.
    #[default]
    Human,
    /// One JSON document for a machine reader.
    Json,
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
