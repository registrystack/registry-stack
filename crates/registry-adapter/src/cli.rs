// SPDX-License-Identifier: Apache-2.0

//! The canonical `adapter` command tree, shared by the runtime binary and
//! the generated Registry Stack CLI catalog.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "adapter",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "The Registry Adapter runtime"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Serve the governed record facade, typed payment connections, or both.
    Serve {
        /// Runtime configuration file.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        runtime_config: PathBuf,
        /// The directory holding project.yaml.
        #[arg(
            long,
            value_name = "DIRECTORY",
            required_unless_present = "payments_config"
        )]
        project: Option<PathBuf>,
        /// Typed payment connections hosted on this listener.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        payments_config: Option<PathBuf>,
        /// Reviewed provider packs for current connections and retained attempts.
        #[arg(long, value_name = "FILE", requires = "payments_config")]
        payment_provider_pack: Vec<PathBuf>,
        /// The profile file; defaults to profile.yaml beside the project.
        #[arg(long, value_name = "FILE", requires = "project")]
        profile: Option<PathBuf>,
        /// The pack file, whose scripts/ sit beside it; defaults to pack.yaml
        /// beside the project.
        #[arg(long, value_name = "FILE", requires = "project")]
        pack: Option<PathBuf>,
    },
    /// Export the record-facade contract without binding a listener.
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn a_payment_only_host_needs_no_record_project() {
        assert!(super::Cli::try_parse_from([
            "adapter",
            "serve",
            "--runtime-config",
            "/runtime.yaml",
            "--payments-config",
            "/payments.yaml"
        ])
        .is_ok());
        assert!(super::Cli::try_parse_from([
            "adapter",
            "serve",
            "--runtime-config",
            "/runtime.yaml"
        ])
        .is_err());
        assert!(super::Cli::try_parse_from([
            "adapter",
            "serve",
            "--runtime-config",
            "/runtime.yaml",
            "--payments-config",
            "/payments.yaml",
            "--payment-provider-pack",
            "/pack.yaml"
        ])
        .is_ok());
        assert!(super::Cli::try_parse_from([
            "adapter",
            "serve",
            "--runtime-config",
            "/runtime.yaml",
            "--payment-provider-pack",
            "/pack.yaml"
        ])
        .is_err());
        assert!(super::Cli::try_parse_from([
            "adapter",
            "serve",
            "--runtime-config",
            "/runtime.yaml",
            "--payments-config",
            "/payments.yaml",
            "--profile",
            "profile.yaml"
        ])
        .is_err());
    }

    #[test]
    fn the_version_is_the_display_version_the_ctl_tools_report() {
        assert_eq!(
            super::command().get_version(),
            Some(registry_platform_buildinfo::DISPLAY_VERSION)
        );
    }

    #[test]
    fn payment_provider_packs_can_be_repeated_for_retained_attempts() {
        let parsed = super::Cli::try_parse_from([
            "adapter",
            "serve",
            "--runtime-config",
            "/runtime.yaml",
            "--payments-config",
            "/payments.yaml",
            "--payment-provider-pack",
            "/pack-a.yaml",
            "--payment-provider-pack",
            "/pack-b.yaml",
        ])
        .unwrap();
        let super::Command::Serve {
            payment_provider_pack,
            ..
        } = parsed.command
        else {
            panic!("the serve command was expected")
        };
        assert_eq!(
            payment_provider_pack,
            vec![
                std::path::PathBuf::from("/pack-a.yaml"),
                std::path::PathBuf::from("/pack-b.yaml")
            ]
        );
    }
}
