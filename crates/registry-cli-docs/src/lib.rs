// SPDX-License-Identifier: Apache-2.0
//! Deterministic reference data derived from released Clap command trees.

use std::ffi::{OsStr, OsString};

use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgGroup, Command,
};
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
    pub constraints: Vec<ConstraintReference>,
    pub subcommands: Vec<CommandReference>,
}

#[derive(Debug, Serialize)]
pub struct ArgumentReference {
    pub display: String,
    pub description: String,
    pub always_required: bool,
    pub default_values: Vec<String>,
    pub possible_values: Vec<String>,
    pub environment: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    RequiredOneOf,
    RequiresAll,
}

#[derive(Debug, Serialize)]
pub struct ConstraintReference {
    pub kind: ConstraintKind,
    pub when: Option<String>,
    pub arguments: Vec<String>,
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
        constraints: command_constraints(&command),
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
        always_required: argument.is_required_set(),
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

fn command_constraints(command: &Command) -> Vec<ConstraintReference> {
    let mut constraints = command
        .get_groups()
        .filter(|group| group.is_required_set())
        .filter_map(|group| {
            let arguments = group_arguments(command, group)
                .into_iter()
                .filter(|argument| !argument.is_hide_set())
                .map(argument_display)
                .collect::<Vec<_>>();
            (!arguments.is_empty()).then_some(ConstraintReference {
                kind: ConstraintKind::RequiredOneOf,
                when: None,
                arguments,
            })
        })
        .collect::<Vec<_>>();

    if command.get_subcommands().next().is_none() {
        constraints.extend(
            command
                .get_arguments()
                .filter(|argument| {
                    !argument.is_hide_set()
                        && argument.get_id() != "help"
                        && argument.get_id() != "version"
                })
                .filter_map(|argument| {
                    let arguments = required_when_present(command, argument);
                    (!arguments.is_empty()).then_some(ConstraintReference {
                        kind: ConstraintKind::RequiresAll,
                        when: Some(argument_display(argument)),
                        arguments,
                    })
                }),
        );
    }
    constraints
}

fn group_arguments<'a>(command: &'a Command, group: &ArgGroup) -> Vec<&'a Arg> {
    fn collect<'a>(
        command: &'a Command,
        group: &ArgGroup,
        arguments: &mut Vec<&'a Arg>,
        visited: &mut Vec<String>,
    ) {
        let group_id = group.get_id().as_str().to_owned();
        if visited.contains(&group_id) {
            return;
        }
        visited.push(group_id);
        for id in group.get_args() {
            if let Some(argument) = command
                .get_arguments()
                .find(|argument| argument.get_id() == id)
            {
                if !arguments
                    .iter()
                    .any(|existing| existing.get_id() == argument.get_id())
                {
                    arguments.push(argument);
                }
            } else if let Some(nested) = command
                .get_groups()
                .find(|candidate| candidate.get_id() == id)
            {
                collect(command, nested, arguments, visited);
            }
        }
    }

    let mut arguments = Vec::new();
    collect(command, group, &mut arguments, &mut Vec::new());
    arguments
}

fn required_when_present(command: &Command, argument: &Arg) -> Vec<String> {
    let selected = baseline_arguments(command, argument);
    let argv = parser_argv(command, &selected);
    let error = match command.clone().try_get_matches_from(argv) {
        Ok(_) => return Vec::new(),
        Err(error) if error.kind() == ErrorKind::MissingRequiredArgument => error,
        Err(_) => return Vec::new(),
    };
    match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::Strings(arguments)) => {
            let mut unique = Vec::new();
            for argument in arguments {
                let argument = normalized(argument);
                if !unique.contains(&argument) {
                    unique.push(argument);
                }
            }
            unique
        }
        _ => Vec::new(),
    }
}

fn baseline_arguments(command: &Command, current: &Arg) -> Vec<String> {
    let mut selected = command
        .get_arguments()
        .filter(|argument| argument.is_required_set())
        .map(|argument| argument.get_id().as_str().to_owned())
        .collect::<Vec<_>>();

    for group in command.get_groups().filter(|group| group.is_required_set()) {
        let members = group_arguments(command, group);
        let choice = members
            .iter()
            .find(|argument| argument.get_id() == current.get_id())
            .copied()
            .or_else(|| members.first().copied());
        if let Some(choice) = choice {
            push_unique(&mut selected, choice.get_id().as_str());
        }
    }
    push_unique(&mut selected, current.get_id().as_str());
    selected
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn parser_argv(command: &Command, selected: &[String]) -> Vec<OsString> {
    let mut argv = vec![OsString::from(command.get_name())];
    for argument in command
        .get_arguments()
        .filter(|argument| argument.get_index().is_none())
        .filter(|argument| selected.iter().any(|id| id == argument.get_id().as_str()))
    {
        argv.extend(argument_tokens(argument));
    }
    let mut positionals = command
        .get_arguments()
        .filter(|argument| argument.get_index().is_some())
        .filter(|argument| selected.iter().any(|id| id == argument.get_id().as_str()))
        .collect::<Vec<_>>();
    positionals.sort_by_key(|argument| argument.get_index());
    for argument in positionals {
        argv.extend(argument_tokens(argument));
    }
    argv
}

fn argument_tokens(argument: &Arg) -> Vec<OsString> {
    let mut tokens = Vec::new();
    if argument.get_index().is_none() {
        if let Some(long) = argument.get_long() {
            tokens.push(OsString::from(format!("--{long}")));
        } else if let Some(short) = argument.get_short() {
            tokens.push(OsString::from(format!("-{short}")));
        } else {
            return tokens;
        }
    }
    if argument.get_action().takes_values() {
        let value_count = argument
            .get_num_args()
            .map(|range| range.min_values().max(1))
            .unwrap_or(1);
        tokens.extend((0..value_count).map(|_| sample_value(argument)));
    }
    tokens
}

fn sample_value(argument: &Arg) -> OsString {
    if let Some(value) = argument
        .get_value_parser()
        .possible_values()
        .and_then(|mut values| values.find(|value| !value.is_hide_set()))
    {
        return OsString::from(value.get_name());
    }
    if let Some(value) = argument.get_default_values().first() {
        return value.to_os_string();
    }
    let name = argument
        .get_value_names()
        .and_then(|names| names.first())
        .map(|name| name.as_str())
        .unwrap_or_else(|| argument.get_id().as_str())
        .to_ascii_uppercase();
    if name.contains("URL") || name.contains("URI") {
        OsString::from("https://example.com")
    } else if name.contains("PORT")
        || name.contains("SECONDS")
        || name.contains("COUNT")
        || name.contains("LIMIT")
        || name.contains("SIZE")
    {
        OsString::from("1")
    } else {
        OsString::from("value")
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
    use clap::ArgAction;

    fn find_command<'a>(
        commands: &'a [CommandReference],
        invocation: &str,
    ) -> &'a CommandReference {
        for command in commands {
            if command.invocation == invocation {
                return command;
            }
            if let Some(found) = command
                .subcommands
                .iter()
                .find(|command| command.invocation == invocation)
            {
                return found;
            }
            if invocation.starts_with(&format!("{} ", command.invocation)) {
                return find_command(&command.subcommands, invocation);
            }
        }
        panic!("missing command {invocation}");
    }

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

    #[test]
    fn parser_constraints_cover_groups_and_argument_requirements() {
        let reference = command_reference(
            Command::new("tool")
                .arg(Arg::new("left").long("left").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("right")
                        .long("right")
                        .action(ArgAction::SetTrue)
                        .requires("detail"),
                )
                .arg(Arg::new("detail").long("detail").action(ArgAction::SetTrue))
                .group(
                    ArgGroup::new("choice")
                        .required(true)
                        .args(["left", "right"]),
                ),
            None,
        );

        assert!(reference.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredOneOf
                && constraint.when.is_none()
                && constraint.arguments == ["--left", "--right"]
        }));
        assert!(reference.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiresAll
                && constraint.when.as_deref() == Some("--right")
                && constraint.arguments == ["--detail"]
        }));
    }

    #[test]
    fn supported_cli_constraints_are_published() {
        let catalog = catalog();
        let audit_show = find_command(&catalog.binaries, "evidencectl audit show");
        assert!(audit_show.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredOneOf
                && constraint.arguments == ["--last-operation"]
        }));

        let inspect = find_command(&catalog.binaries, "relayctl inspect");
        let statistical_view = inspect
            .constraints
            .iter()
            .find(|constraint| {
                constraint.kind == ConstraintKind::RequiresAll
                    && constraint.when.as_deref() == Some("--statistical-view <VIEW>")
            })
            .expect("statistical view constraint");
        for required in [
            "--starters <DIRECTORY>",
            "--time-column <COLUMN>",
            "--measure-column <COLUMN>",
        ] {
            assert!(
                statistical_view
                    .arguments
                    .iter()
                    .any(|argument| argument == required),
                "statistical view did not require {required}"
            );
        }
    }
}
