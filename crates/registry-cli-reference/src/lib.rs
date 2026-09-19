// SPDX-License-Identifier: Apache-2.0
//! Deterministic reference data derived from a Registry Stack Clap command
//! tree. Shared by the offline `registry-cli-docs` catalog and the
//! `help --format json` surface each binary renders itself, so one walker
//! produces both.

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
};

use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgGroup, Command,
};
use serde::Serialize;

pub const SCHEMA_VERSION: &str = "registry.cli-reference/v2";

/// Clap value names that stand for a filesystem path the operator supplies.
pub const PATH_VALUE_NAMES: [&str; 7] = [
    "ABSOLUTE_DIRECTORY",
    "ABSOLUTE_FILE",
    "DESTINATION",
    "DIRECTORY",
    "FILE",
    "JSON_FILE",
    "PROJECT",
];

/// The rule a command line applies when it resolves an operator path one
/// component at a time through the directory that holds it. The generator
/// states it for every path argument of such a command line, so each flag's own
/// help stays about what its file or directory is for.
pub const SYMBOLIC_LINK_REFUSAL: &str = "A symbolic link at any component of this path is refused.";

#[derive(Debug, Serialize)]
pub struct Catalog {
    pub schema_version: &'static str,
    pub source_version: &'static str,
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
    pub repeatable: bool,
    pub default_values: Vec<String>,
    pub possible_values: Vec<String>,
    pub environment: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    RequiredExactlyOne,
    RequiredOneOrMore,
    RequiresAll,
    MutuallyExclusive,
}

#[derive(Debug, Serialize)]
pub struct ConstraintReference {
    pub kind: ConstraintKind,
    pub when: Option<String>,
    pub arguments: Vec<String>,
}

/// Build reference data for one command tree. `path_note` is stated for every
/// path argument the tree publishes, so a rule the whole command line applies
/// is written once here instead of in each flag's help.
pub fn command_reference(
    mut command: Command,
    parent: Option<&str>,
    path_note: Option<&'static str>,
) -> CommandReference {
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
        let reference = argument_reference(&command, argument, path_note);
        if argument.get_index().is_some() {
            arguments.push(reference);
        } else {
            options.push(reference);
        }
    }

    let subcommands = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set() && subcommand.get_name() != "help")
        .map(|subcommand| command_reference(subcommand.clone(), Some(&invocation), path_note))
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

fn argument_reference(
    command: &Command,
    argument: &Arg,
    path_note: Option<&'static str>,
) -> ArgumentReference {
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
    let mut description = argument
        .get_long_help()
        .or_else(|| argument.get_help())
        .map(ToString::to_string)
        .map(|value| normalized(&value))
        .unwrap_or_default();
    assert!(
        !description.is_empty(),
        "{} argument {} lacks public help",
        command.get_name(),
        argument_display(argument)
    );
    if let Some(note) = path_note.filter(|_| is_path_argument(argument)) {
        description = format!("{} {note}", sentence(&description));
    }
    ArgumentReference {
        display: argument_display(argument),
        description,
        always_required: argument.is_required_set()
            && argument.get_env().is_none()
            && !(command.is_subcommand_negates_reqs_set()
                && command.get_subcommands().next().is_some()),
        repeatable: matches!(
            argument.get_action(),
            clap::ArgAction::Append | clap::ArgAction::Count
        ),
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
            let mut group = group.clone();
            let kind = if group.is_multiple() {
                ConstraintKind::RequiredOneOrMore
            } else {
                ConstraintKind::RequiredExactlyOne
            };
            let arguments = group_arguments(command, &group)
                .into_iter()
                .filter(|argument| !argument.is_hide_set())
                .map(argument_display)
                .collect::<Vec<_>>();
            (!arguments.is_empty()).then_some(ConstraintReference {
                kind,
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
    constraints.extend(conflict_constraints(command));
    constraints
}

fn conflict_constraints(command: &Command) -> Vec<ConstraintReference> {
    let public_arguments = command
        .get_arguments()
        .filter(|argument| is_public_argument(argument))
        .collect::<Vec<_>>();
    let public_ids = public_arguments
        .iter()
        .map(|argument| argument.get_id().as_str())
        .collect::<BTreeSet<_>>();
    let mut pairs = BTreeSet::new();
    for argument in &public_arguments {
        for conflicting in command
            .get_arg_conflicts_with(argument)
            .into_iter()
            .filter(|conflicting| public_ids.contains(conflicting.get_id().as_str()))
        {
            let mut pair = [argument_display(argument), argument_display(conflicting)];
            pair.sort();
            if pair[0] != pair[1] {
                pairs.insert(pair);
            }
        }
        if argument.is_exclusive_set() {
            for other in &public_arguments {
                let mut pair = [argument_display(argument), argument_display(other)];
                pair.sort();
                if pair[0] != pair[1] {
                    pairs.insert(pair);
                }
            }
        }
    }
    for group in command.get_groups() {
        let mut group = group.clone();
        if group.is_multiple() {
            continue;
        }
        let arguments = group_arguments(command, &group)
            .into_iter()
            .filter(|argument| is_public_argument(argument))
            .map(argument_display)
            .collect::<Vec<_>>();
        for (index, left) in arguments.iter().enumerate() {
            for right in arguments.iter().skip(index + 1) {
                let mut pair = [left.clone(), right.clone()];
                pair.sort();
                if pair[0] != pair[1] {
                    pairs.insert(pair);
                }
            }
        }
    }
    pairs
        .into_iter()
        .map(|arguments| ConstraintReference {
            kind: ConstraintKind::MutuallyExclusive,
            when: None,
            arguments: arguments.into(),
        })
        .collect()
}

/// Report whether an argument's value is a filesystem path the operator names.
fn is_path_argument(argument: &Arg) -> bool {
    argument.get_value_names().is_some_and(|names| {
        names
            .iter()
            .any(|name| PATH_VALUE_NAMES.contains(&name.as_str()))
    })
}

/// End a help sentence, so an appended rule reads as its own sentence.
fn sentence(value: &str) -> String {
    if value.ends_with(['.', '!', '?']) {
        value.to_owned()
    } else {
        format!("{value}.")
    }
}

fn is_public_argument(argument: &Arg) -> bool {
    !argument.is_hide_set() && argument.get_id() != "help" && argument.get_id() != "version"
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
    // Probe conditional requirements independently of required arguments and
    // groups, which are already documented separately. Choosing a group's
    // first member would attach that mode's requirements to unrelated flags.
    let mut probe = command
        .clone()
        .mut_args(|argument| argument.required(false));
    for group in command.get_groups().filter(|group| group.is_required_set()) {
        probe = probe.mut_group(group.get_id().as_str(), |group| group.required(false));
    }

    // Earlier positionals must be supplied to reach the current one. Remove
    // their requirements from the result so only this argument is the trigger.
    let mut selected = command
        .get_positionals()
        .filter(|previous| {
            previous
                .get_index()
                .zip(argument.get_index())
                .is_some_and(|(previous, current)| previous < current)
        })
        .map(|previous| previous.get_id().as_str().to_owned())
        .collect::<Vec<_>>();
    let baseline = missing_required_arguments(&probe, &selected);
    selected.push(argument.get_id().as_str().to_owned());
    missing_required_arguments(&probe, &selected)
        .into_iter()
        .filter(|required| !baseline.contains(required))
        .collect()
}

fn missing_required_arguments(command: &Command, selected: &[String]) -> Vec<String> {
    let argv = parser_argv(command, selected);
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

/// Build a single-binary catalog for the binary's own machine-readable help.
///
/// `source_version` is the version text the binary itself reports, so
/// `evidencectl help --format json` and the offline catalog agree.
pub fn binary_catalog(
    command: Command,
    source_version: &'static str,
    path_note: Option<&'static str>,
) -> Catalog {
    Catalog {
        schema_version: SCHEMA_VERSION,
        source_version,
        binaries: vec![command_reference(command, None, path_note)],
    }
}
