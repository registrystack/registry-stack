// SPDX-License-Identifier: Apache-2.0
//! Relay runtime command-line contract.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

const DEFAULT_HEALTHCHECK_URL: &str = "http://127.0.0.1:8080/health";

#[derive(Debug, Parser)]
#[command(
    name = "relay",
    about = "Compiled read-only Registry Relay runtime",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify and activate one sealed Registry package, then serve it.
    Serve {
        /// Strict deployment binding for the sealed package and local resources.
        #[arg(long, env = "RELAY_RUNTIME")]
        runtime: PathBuf,
    },
    /// Probe an unauthenticated Relay liveness endpoint.
    Healthcheck {
        /// Complete HTTP(S) URL of the Relay `/health` endpoint.
        #[arg(
            long,
            env = "RELAY_HEALTHCHECK_URL",
            default_value = DEFAULT_HEALTHCHECK_URL
        )]
        url: String,
    },
}

/// Return the complete public command tree without running Relay.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn healthcheck_endpoint_has_a_safe_configurable_default() {
        let command = command();
        let healthcheck = command
            .find_subcommand("healthcheck")
            .expect("healthcheck subcommand exists");
        let url = healthcheck
            .get_arguments()
            .find(|argument| argument.get_id() == "url")
            .expect("healthcheck URL argument exists");
        assert_eq!(url.get_env(), Some(OsStr::new("RELAY_HEALTHCHECK_URL")));
        assert_eq!(
            url.get_default_values(),
            [OsStr::new(DEFAULT_HEALTHCHECK_URL)]
        );
    }
}
