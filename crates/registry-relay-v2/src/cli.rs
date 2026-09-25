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
    /// Validate the sealed package and every deployment dependency without
    /// taking the listener socket.
    Check {
        /// Absolute path of the runtime configuration that binds the sealed
        /// package to local resources.
        #[arg(long = "runtime-config", value_name = "FILE")]
        runtime_config: PathBuf,
        /// Also prove the configured audit file resolves inside this absolute
        /// directory, which the deployment declares persistent.
        ///
        /// The declared root is a storage boundary, not a second audit setting.
        /// Relay resolves the runtime audit path exactly as startup resolves it
        /// and refuses when the result is not at or below the root, which is
        /// what stops a container from mounting durable storage at the
        /// conventional prefix while writing audit somewhere ephemeral. A
        /// `stdout` audit destination has no path to prove and is refused.
        #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
        require_audit_under: Option<PathBuf>,
    },
    /// Verify and activate one sealed Registry package, then serve it.
    Serve {
        /// Absolute path of the runtime configuration that binds the sealed
        /// package to local resources.
        #[arg(long = "runtime-config", value_name = "FILE")]
        runtime_config: PathBuf,
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

    #[test]
    fn check_can_require_an_operator_declared_persistent_audit_root() {
        let parsed = Cli::try_parse_from([
            "relay",
            "check",
            "--runtime-config",
            "/etc/relay/runtime.yaml",
            "--require-audit-under",
            "/var/lib/relay/audit",
        ])
        .expect("the declared audit root parses");
        let Command::Check {
            require_audit_under,
            ..
        } = parsed.command
        else {
            panic!("check parsed as another command");
        };
        assert_eq!(
            Some(PathBuf::from("/var/lib/relay/audit")),
            require_audit_under
        );

        // The claim is an addition to the existing check, never a replacement.
        let plain = Cli::try_parse_from([
            "relay",
            "check",
            "--runtime-config",
            "/etc/relay/runtime.yaml",
        ])
        .expect("check parses without it");
        assert!(matches!(
            plain.command,
            Command::Check {
                require_audit_under: None,
                ..
            }
        ));
    }

    #[test]
    fn the_runtime_configuration_is_named_explicitly_on_every_command() {
        for subcommand in ["check", "serve"] {
            let command = command();
            let found = command
                .find_subcommand(subcommand)
                .expect("subcommand exists");
            let runtime = found
                .get_arguments()
                .find(|argument| argument.get_id() == "runtime_config")
                .expect("runtime configuration argument exists");
            assert_eq!(runtime.get_long(), Some("runtime-config"));
            assert_eq!(runtime.get_env(), None, "{subcommand}");
            assert!(runtime.get_default_values().is_empty(), "{subcommand}");
            assert!(runtime.is_required_set(), "{subcommand}");
            assert!(Cli::try_parse_from(["relay", subcommand]).is_err());
            assert!(Cli::try_parse_from([
                "relay",
                subcommand,
                "--runtime",
                "/etc/relay/runtime.yaml"
            ])
            .is_err());
        }
    }
}
