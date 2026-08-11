// SPDX-License-Identifier: Apache-2.0
//! Deterministic reference data derived from released Clap command trees.

use std::ffi::OsStr;

use clap::{Arg, Command};
use serde::Serialize;

pub const SCHEMA_VERSION: &str = "registry.cli-reference/v1";

#[derive(Debug, Serialize)]
pub struct Catalog {
    pub schema_version: &'static str,
    pub binaries: Vec<CommandReference>,
}

#[derive(Debug, Serialize)]
pub struct CommandReference {
    pub name: String,
    pub invocation: String,
    pub about: String,
    pub long_about: Option<String>,
    pub usage: String,
    pub arguments: Vec<ArgumentReference>,
    pub options: Vec<ArgumentReference>,
    pub subcommands: Vec<CommandReference>,
}

#[derive(Debug, Serialize)]
pub struct ArgumentReference {
    pub display: String,
    pub description: String,
    pub required: bool,
    pub default_values: Vec<String>,
    pub possible_values: Vec<String>,
    pub environment: Option<String>,
}

/// Build reference data for every released Relay and Evidence command line.
pub fn catalog() -> Catalog {
    let mut binaries = vec![
        command_reference(registry_evidence::command(), None),
        command_reference(registry_evidence_oid4vci::command(), None),
        command_reference(registry_evidencectl::command(), None),
        command_reference(registry_mint::command(), None),
        command_reference(registry_relay_v2::command(), None),
        command_reference(registry_relayctl::command(), None),
    ];
    binaries.sort_by(|left, right| left.name.cmp(&right.name));
    Catalog {
        schema_version: SCHEMA_VERSION,
        binaries,
    }
}

fn command_reference(mut command: Command, parent: Option<&str>) -> CommandReference {
    command.build();
    let name = command.get_name().to_owned();
    let invocation = parent.map_or_else(|| name.clone(), |parent| format!("{parent} {name}"));
    let about = command
        .get_about()
        .map(ToString::to_string)
        .map(|value| normalized(&value))
        .unwrap_or_else(|| name.clone());
    let long_about = command
        .get_long_about()
        .map(ToString::to_string)
        .map(|value| normalized(&value))
        .filter(|value| value != &about);
    let usage = command
        .clone()
        .render_usage()
        .to_string()
        .strip_prefix("Usage: ")
        .unwrap_or_else(|| command.get_name())
        .to_owned();

    let mut arguments = Vec::new();
    let mut options = Vec::new();
    for argument in command
        .get_arguments()
        .filter(|argument| !argument.is_hide_set())
    {
        let reference = argument_reference(argument);
        if argument.get_index().is_some() {
            arguments.push(reference);
        } else {
            options.push(reference);
        }
    }

    let subcommands = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set() && subcommand.get_name() != "help")
        .map(|subcommand| command_reference(subcommand.clone(), Some(&invocation)))
        .collect();

    CommandReference {
        name,
        invocation,
        about,
        long_about,
        usage,
        arguments,
        options,
        subcommands,
    }
}

fn argument_reference(argument: &Arg) -> ArgumentReference {
    let takes_values = argument.get_action().takes_values();
    let possible_values = if takes_values {
        argument
            .get_value_parser()
            .possible_values()
            .map(|values| {
                values
                    .filter(|value| !value.is_hide_set())
                    .map(|value| value.get_name().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    ArgumentReference {
        display: argument_display(argument),
        description: argument
            .get_long_help()
            .or_else(|| argument.get_help())
            .map(ToString::to_string)
            .map(|value| normalized(&value))
            .unwrap_or_default(),
        required: argument.is_required_set(),
        default_values: if takes_values {
            argument
                .get_default_values()
                .iter()
                .map(|value| os_string(value))
                .collect()
        } else {
            Vec::new()
        },
        possible_values,
        environment: argument.get_env().map(os_string),
    }
}

fn argument_display(argument: &Arg) -> String {
    let value_names = argument
        .get_value_names()
        .map(|names| {
            names
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| argument.get_id().as_str().to_uppercase());
    if argument.get_index().is_some() {
        return if argument.is_required_set() {
            format!("<{value_names}>")
        } else {
            format!("[{value_names}]")
        };
    }

    let mut flags = Vec::new();
    if let Some(short) = argument.get_short() {
        flags.push(format!("-{short}"));
    }
    if let Some(long) = argument.get_long() {
        flags.push(format!("--{long}"));
    }
    let flags = flags.join(", ");
    if argument.get_action().takes_values() {
        format!("{flags} <{value_names}>")
    } else {
        flags
    }
}

fn normalized(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn os_string(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_every_released_evidence_and_relay_binary() {
        assert_eq!(
            catalog()
                .binaries
                .iter()
                .map(|command| command.name.as_str())
                .collect::<Vec<_>>(),
            [
                "evidence",
                "evidence-oid4vci",
                "evidencectl",
                "mint",
                "relay",
                "relayctl",
            ]
        );
    }

    #[test]
    fn hidden_implementation_commands_never_enter_the_catalog() {
        let rendered = serde_json::to_string(&catalog()).expect("render catalog");
        for hidden in [
            "__dev-supervisor",
            "bundle-check",
            "bundle-evaluate",
            "prepare-local-relying-procedure",
            "local-audit-last-operation",
        ] {
            assert!(
                !rendered.contains(hidden),
                "published hidden command {hidden}"
            );
        }
    }

    #[test]
    fn every_published_command_has_usage_and_a_description() {
        fn check(command: &CommandReference) {
            assert!(
                !command.about.is_empty(),
                "{} lacks about text",
                command.invocation
            );
            assert!(
                !command.usage.is_empty(),
                "{} lacks usage",
                command.invocation
            );
            for subcommand in &command.subcommands {
                check(subcommand);
            }
        }
        for command in &catalog().binaries {
            check(command);
        }
    }
}
