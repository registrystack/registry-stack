//! Evidence wallet verifier command-line contract.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "evidence-oid4vp",
    about = "Registry Stack OpenID4VP verifier front end for Evidence",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check the runtime file offline, as `serve` reads it, then exit.
    ///
    /// Reads the one file and nothing else: no network, no socket, and no
    /// secret material. It does not prove that the certificate chain and
    /// signing key resolve, match, or are unexpired: `serve` proves all three
    /// when it starts.
    /// Exits 0 when nothing is refused, 1 when something is refused or, under
    /// --deny-warnings, a warning is reported, 2 when the command line is
    /// invalid, and 3 when the file cannot be read.
    Check {
        /// Runtime configuration file.
        #[arg(
            long = "runtime-config",
            value_name = "FILE",
            env = "EVIDENCE_OID4VP_RUNTIME_CONFIG"
        )]
        config: PathBuf,
        /// Emit the selected command's report in this format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        /// Exit 1 when a warning is reported.
        #[arg(long)]
        deny_warnings: bool,
        /// Fill `${NAME}` expressions in the runtime file from the process
        /// environment and check the values they produce. Without it, each
        /// expression is checked by syntax and position only.
        #[arg(long)]
        environment: bool,
    },
    /// Render the deterministic OpenAPI 3.1 contract, then exit.
    Openapi {
        /// Write to a file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Serve the portal and wallet endpoints until terminated.
    Serve {
        /// Runtime configuration file.
        #[arg(
            long = "runtime-config",
            value_name = "FILE",
            env = "EVIDENCE_OID4VP_RUNTIME_CONFIG"
        )]
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
    fn runtime_inputs_use_the_named_flag_and_environment() {
        for name in ["check", "serve"] {
            assert!(Cli::try_parse_from([
                "evidence-oid4vp",
                name,
                "--runtime-config",
                "runtime.yaml"
            ])
            .is_ok());
            assert!(
                Cli::try_parse_from(["evidence-oid4vp", name, "--config", "runtime.yaml"]).is_err()
            );
            let tree = command();
            let option = tree
                .find_subcommand(name)
                .unwrap()
                .get_arguments()
                .find(|argument| argument.get_long() == Some("runtime-config"))
                .unwrap();
            assert_eq!(option.get_env().unwrap(), "EVIDENCE_OID4VP_RUNTIME_CONFIG");
        }
    }

    #[test]
    fn every_config_option_has_public_help() {
        let command = command();
        for name in ["check", "serve"] {
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
                "{name} --runtime-config lacks public help"
            );
        }
    }
}
