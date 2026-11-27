// SPDX-License-Identifier: Apache-2.0

//! A small session service beside a gateway.
//!
//! A person signs in once through the service. It keeps their tokens on the
//! server and gives the browser one opaque cookie. The gateway asks the service,
//! on every call to a signed-in route, which bearer token to attach: the service
//! checks, it never proxies.

pub mod check;
pub mod clock;
pub mod config;
pub mod gateway;
pub mod grants;
pub mod issuer;
pub mod journal;
pub mod offline;
pub mod pages;
mod public;
pub mod revoker;
pub mod runtime;
mod signin;
pub mod store;
pub mod wire;

use std::path::PathBuf;

use clap::{value_parser, Arg, ArgAction, ArgGroup, Command};

use crate::offline::OutputFormat;

/// The complete clap command tree, built so help and the CLI reference can
/// render it.
#[must_use]
pub fn command() -> Command {
    Command::new("registry-session")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .about("Serve the session service beside a gateway, or check its runtime file")
        .arg(
            Arg::new("runtime-config")
                .long("runtime-config")
                .value_name("FILE")
                .help("Runtime configuration file (every command but `gateway envoy --verify-assembled`)")
                .value_parser(value_parser!(PathBuf)),
        )
        .subcommand(
            Command::new("check")
                .about("Check the runtime file offline, reading no secret and opening no socket")
                .long_about(
                    "Check the runtime file offline, reading no secret and opening no socket.\n\n\
                     The check reads the runtime file as the service does, with no secret \
                     material, network call, audit file, or listener. It does not prove that a \
                     secret the file names resolves or that the audit directory can be opened: \
                     the service proves both when it starts.",
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .help("Emit the report in this format")
                        .value_parser(value_parser!(OutputFormat))
                        .default_value("human"),
                )
                .arg(
                    Arg::new("deny-warnings")
                        .long("deny-warnings")
                        .help("Exit 1 when a warning is reported")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .help(
                            "Fill `${NAME}` expressions in the runtime file from the process \
                             environment and check the values they produce. Without it, each \
                             expression is checked by syntax and position only",
                        )
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("identity-receipt")
                        .long("identity-receipt")
                        .value_name("FILE")
                        .help(
                            "Also check the runtime file against the identity generator's \
                             receipt: the person audience and each kind of sign-in's audiences \
                             must match, and a module on the person audience must carry a member \
                             product's name as its id. `${NAME}` expressions are not resolved \
                             unless --environment is given",
                        )
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("gateway")
                .about("Generate gateway configuration from the runtime file")
                .subcommand_required(true)
                .subcommand(
                    Command::new("envoy")
                        .about("Write or compare the Envoy configuration fragments")
                        .group(
                            ArgGroup::new("mode")
                                .args(["out", "check", "verify-assembled"])
                                .required(true)
                                                .multiple(false),
                        )
                        .arg(
                            Arg::new("out")
                                .long("out")
                                .value_name("DIR")
                                .help("Write the fragments into this directory")
                                .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            Arg::new("check")
                                .long("check")
                                .value_name("DIR")
                                .help("Compare the fragments with the ones in this directory")
                                .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            Arg::new("verify-assembled")
                                .long("verify-assembled")
                                .value_name("FILE")
                                .help("Verify an assembled Envoy configuration file")
                                .value_parser(value_parser!(PathBuf)),
                        ),
                ),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parses(arguments: &[&str]) -> bool {
        let mut all = vec!["registry-session"];
        all.extend_from_slice(arguments);
        command().try_get_matches_from(all).is_ok()
    }

    #[test]
    fn the_command_is_well_formed() {
        command().debug_assert();
    }

    #[test]
    fn a_gateway_mode_is_exactly_one_of_out_check_and_verify_assembled() {
        let envoy = ["--runtime-config", "/r.yaml", "gateway", "envoy"];
        let with = |extra: &[&str]| parses(&[&envoy[..], extra].concat());
        assert!(with(&["--out", "/d"]));
        assert!(with(&["--check", "/d"]));
        assert!(with(&["--verify-assembled", "/e.yaml"]));
        assert!(!with(&[]));
        assert!(!with(&["--out", "/d", "--check", "/d"]));
        assert!(!with(&["--out", "/d", "--verify-assembled", "/e.yaml"]));
        assert!(!with(&["--check", "/d", "--verify-assembled", "/e.yaml"]));
        assert!(!with(&[
            "--out",
            "/d",
            "--check",
            "/d",
            "--verify-assembled",
            "/e.yaml"
        ]));
        // Verifying an assembled file reads no runtime file.
        assert!(parses(&[
            "gateway",
            "envoy",
            "--verify-assembled",
            "/e.yaml"
        ]));
    }
}
