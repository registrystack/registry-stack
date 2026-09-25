// SPDX-License-Identifier: Apache-2.0
//! Deterministic reference data derived from Registry Stack Clap command trees.

pub use registry_cli_reference::{
    command_reference, ArgumentReference, Catalog, CommandReference, ConstraintKind,
    ConstraintReference, PATH_VALUE_NAMES, SCHEMA_VERSION, SYMBOLIC_LINK_REFUSAL,
};

/// Build reference data for the supported Registry Stack command lines.
pub fn catalog() -> Catalog {
    let mut binaries = vec![
        command_reference(registry_evidence::command(), None, None),
        command_reference(registry_evidence_oid4vci::command(), None, None),
        command_reference(registry_evidencectl::command(), None, None),
        command_reference(registry_caseworkctl::command(), None, None),
        command_reference(registry_casework::command(), None, None),
        command_reference(registry_scheduling::runtime::command(), None, None),
        command_reference(registry_schedulingctl::command(), None, None),
        command_reference(registry_breg::command(), None, None),
        command_reference(registry_breg_mcp::command(), None, None),
        command_reference(registry_breg_review::command(), None, None),
        command_reference(
            registry_bregctl::command(),
            None,
            Some(SYMBOLIC_LINK_REFUSAL),
        ),
        command_reference(registry_render::command(), None, None),
        command_reference(registry_relay_v2::command(), None, None),
        command_reference(registry_relayctl::command(), None, None),
    ];
    binaries.sort_by(|left, right| left.name.cmp(&right.name));
    Catalog {
        schema_version: SCHEMA_VERSION,
        source_version: env!("CARGO_PKG_VERSION"),
        binaries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, ArgGroup, Command};
    use std::collections::BTreeSet;

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

    fn has_conflict(command: &CommandReference, left: &str, right: &str) -> bool {
        let mut arguments = [left, right];
        arguments.sort();
        command.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::MutuallyExclusive
                && constraint.when.is_none()
                && constraint.arguments == arguments
        })
    }

    #[test]
    fn catalog_contains_every_supported_public_binary() {
        let catalog = catalog();
        assert_eq!(catalog.source_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            catalog
                .binaries
                .iter()
                .map(|command| command.name.as_str())
                .collect::<Vec<_>>(),
            [
                "breg",
                "breg-mcp",
                "breg-review",
                "bregctl",
                "casework",
                "caseworkctl",
                "evidence",
                "evidence-oid4vci",
                "evidencectl",
                "registry-render",
                "relay",
                "relayctl",
                "scheduling",
                "schedulingctl",
            ]
        );
    }

    #[test]
    fn registry_render_publishes_its_bundle_and_serve_commands() {
        let catalog = catalog();
        for invocation in [
            "registry-render init",
            "registry-render check",
            "registry-render validate",
            "registry-render seal",
            "registry-render compile",
            "registry-render serve",
            "registry-render healthcheck",
            "registry-render audit-verify",
        ] {
            assert!(!find_command(&catalog.binaries, invocation).usage.is_empty());
        }
    }

    #[test]
    fn breg_configuration_and_webhook_commands_are_published() {
        let catalog = catalog();
        let breg = find_command(&catalog.binaries, "breg");
        assert!(breg.options.iter().any(|option| {
            option.display == "--config <ABSOLUTE_FILE>" && option.always_required
        }));
        let generate = find_command(&catalog.binaries, "bregctl generate");
        assert!(generate.arguments.iter().any(|argument| {
            argument.possible_values
                == [
                    "openapi",
                    "schemas",
                    "actions",
                    "manifest",
                    "metadata",
                    "sql",
                    "evidence-source",
                ]
        }));
        for invocation in [
            "bregctl explain",
            "bregctl webhook sample",
            "bregctl webhook list",
            "bregctl webhook replay",
        ] {
            assert!(!find_command(&catalog.binaries, invocation).usage.is_empty());
        }
    }

    #[test]
    fn every_bregctl_path_argument_states_the_symbolic_link_refusal() {
        // `argument_display` writes a required positional as `<NAME>` and an
        // optional one as `[NAME]`, so both bracket forms name a path value.
        fn is_path_display(display: &str) -> bool {
            PATH_VALUE_NAMES.iter().any(|name| {
                display.contains(&format!("<{name}>")) || display.contains(&format!("[{name}]"))
            })
        }

        fn check(command: &CommandReference, counted: &mut usize) {
            for argument in command.arguments.iter().chain(&command.options) {
                let stated = argument.description.matches(SYMBOLIC_LINK_REFUSAL).count();
                if is_path_display(&argument.display) {
                    assert_eq!(
                        stated, 1,
                        "{} {} states the symbolic link refusal {stated} times: {}",
                        command.invocation, argument.display, argument.description
                    );
                    *counted += 1;
                } else {
                    assert_eq!(
                        stated, 0,
                        "{} {} states the symbolic link refusal for a value that is not a path",
                        command.invocation, argument.display
                    );
                }
            }
            for subcommand in &command.subcommands {
                check(subcommand, counted);
            }
        }

        let catalog = catalog();
        let mut counted = 0;
        check(find_command(&catalog.binaries, "bregctl"), &mut counted);
        assert!(
            counted > 20,
            "the bregctl reference publishes {counted} path arguments"
        );
    }

    #[test]
    fn a_command_line_that_does_not_apply_the_rule_never_states_it() {
        let catalog = catalog();
        for name in ["breg", "evidencectl", "relayctl"] {
            let rendered = serde_json::to_string(find_command(&catalog.binaries, name))
                .expect("render command");
            assert!(
                !rendered.contains(SYMBOLIC_LINK_REFUSAL),
                "{name} states a refusal its own paths were not checked against"
            );
        }
    }

    #[test]
    fn hidden_implementation_commands_never_enter_the_catalog() {
        let rendered = serde_json::to_string(&catalog()).expect("render catalog");
        for hidden in [
            "__dev-supervisor",
            "__worker",
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
            for argument in command.arguments.iter().chain(&command.options) {
                assert!(
                    !argument.description.is_empty(),
                    "{} {} lacks help text",
                    command.invocation,
                    argument.display
                );
            }
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
                .arg(
                    Arg::new("left")
                        .long("left")
                        .help("Select the left mode")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("right")
                        .long("right")
                        .help("Select the right mode")
                        .action(ArgAction::SetTrue)
                        .requires("detail"),
                )
                .arg(
                    Arg::new("detail")
                        .long("detail")
                        .help("Supply mode details")
                        .action(ArgAction::SetTrue),
                )
                .group(
                    ArgGroup::new("choice")
                        .required(true)
                        .args(["left", "right"]),
                ),
            None,
            None,
        );

        assert!(reference.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredExactlyOne
                && constraint.when.is_none()
                && constraint.arguments == ["--left", "--right"]
        }));
        assert!(reference.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiresAll
                && constraint.when.as_deref() == Some("--right")
                && constraint.arguments == ["--detail"]
        }));

        let multiple = command_reference(
            Command::new("tool")
                .arg(
                    Arg::new("first")
                        .long("first")
                        .help("Select the first mode")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("second")
                        .long("second")
                        .help("Select the second mode")
                        .action(ArgAction::SetTrue),
                )
                .group(
                    ArgGroup::new("choices")
                        .required(true)
                        .multiple(true)
                        .args(["first", "second"]),
                ),
            None,
            None,
        );
        assert!(multiple.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredOneOrMore
                && constraint.arguments == ["--first", "--second"]
        }));
    }

    #[test]
    fn planner_test_requirements_match_both_accepted_modes() {
        let parser = registry_bregctl::command();
        for arguments in [
            vec![
                "bregctl",
                "project",
                "planner-test",
                "example-project",
                "--entity",
                "change-request",
                "--request",
                "request.json",
                "--format",
                "json",
            ],
            vec![
                "bregctl",
                "project",
                "planner-test",
                "example-project",
                "--action",
                "register-person",
                "--input",
                "input.json",
                "--expect",
                "expected.json",
                "--format",
                "json",
            ],
        ] {
            parser
                .clone()
                .try_get_matches_from(arguments)
                .expect("documented planner-test mode parses");
        }

        let reference = command_reference(parser, None, None);
        let planner_test = find_command(&[reference], "bregctl project planner-test")
            .constraints
            .iter()
            .filter(|constraint| constraint.kind == ConstraintKind::RequiresAll)
            .map(|constraint| {
                let mut arguments = constraint.arguments.clone();
                arguments.sort();
                (
                    constraint.when.clone().expect("requirement trigger"),
                    arguments,
                )
            })
            .collect::<BTreeSet<_>>();
        let expected = [
            ("--entity <ENTITY>", vec!["--request <JSON_FILE>"]),
            ("--request <JSON_FILE>", vec!["--entity <ENTITY>"]),
            ("--action <ACTION>", vec!["--input <JSON_FILE>"]),
            ("--input <JSON_FILE>", vec!["--action <ACTION>"]),
            (
                "--expect <JSON_FILE>",
                vec!["--action <ACTION>", "--input <JSON_FILE>"],
            ),
        ]
        .into_iter()
        .map(|(when, arguments)| {
            (
                when.to_owned(),
                arguments.into_iter().map(str::to_owned).collect(),
            )
        })
        .collect::<BTreeSet<_>>();
        assert_eq!(planner_test, expected);
    }

    #[test]
    fn positional_requirements_are_not_attributed_to_other_arguments() {
        let reference = command_reference(
            Command::new("tool")
                .arg(
                    Arg::new("source")
                        .help("Source document")
                        .required(true)
                        .requires("schema"),
                )
                .arg(
                    Arg::new("destination")
                        .help("Destination document")
                        .required(true)
                        .requires("format"),
                )
                .arg(
                    Arg::new("schema")
                        .long("schema")
                        .value_name("SCHEMA")
                        .help("Source schema"),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_name("FORMAT")
                        .help("Destination format"),
                )
                .arg(
                    Arg::new("verbose")
                        .long("verbose")
                        .help("Show details")
                        .action(ArgAction::SetTrue),
                ),
            None,
            None,
        );

        let requirements = reference
            .constraints
            .iter()
            .filter(|constraint| constraint.kind == ConstraintKind::RequiresAll)
            .map(|constraint| (constraint.when.as_deref(), constraint.arguments.as_slice()))
            .collect::<Vec<_>>();
        assert_eq!(
            requirements,
            [
                (
                    Some("<SOURCE>"),
                    ["--schema <SCHEMA>".to_owned()].as_slice()
                ),
                (
                    Some("<DESTINATION>"),
                    ["--format <FORMAT>".to_owned()].as_slice(),
                ),
            ]
        );
    }

    #[test]
    fn an_environment_binding_is_an_alternative_to_a_required_option() {
        let reference = command_reference(
            Command::new("tool").arg(
                Arg::new("config")
                    .long("config")
                    .help("Configuration file")
                    .env("TOOL_CONFIG")
                    .required(true),
            ),
            None,
            None,
        );

        let config = reference
            .options
            .iter()
            .find(|argument| argument.display == "--config <CONFIG>")
            .expect("config option");
        assert!(!config.always_required);
        assert_eq!(config.environment.as_deref(), Some("TOOL_CONFIG"));
    }

    #[test]
    fn conflicts_are_deduplicated_and_sorted() {
        let reference = command_reference(
            Command::new("tool")
                .arg(
                    Arg::new("gamma")
                        .long("gamma")
                        .help("Select gamma")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("beta")
                        .long("beta")
                        .help("Select beta")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("alpha"),
                )
                .arg(
                    Arg::new("alpha")
                        .long("alpha")
                        .help("Select alpha")
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["gamma", "beta"]),
                ),
            None,
            None,
        );

        let conflicts = reference
            .constraints
            .iter()
            .filter(|constraint| constraint.kind == ConstraintKind::MutuallyExclusive)
            .map(|constraint| constraint.arguments.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(
            conflicts,
            [
                ["--alpha", "--beta"].as_slice(),
                ["--alpha", "--gamma"].as_slice(),
            ]
        );
    }

    #[test]
    fn optional_groups_and_exclusive_arguments_publish_all_conflicts() {
        let reference = command_reference(
            Command::new("tool")
                .arg(
                    Arg::new("left")
                        .long("left")
                        .help("Select left")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("right")
                        .long("right")
                        .help("Select right")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("alone")
                        .long("alone")
                        .help("Run alone")
                        .exclusive(true)
                        .action(ArgAction::SetTrue),
                )
                .group(ArgGroup::new("side").args(["left", "right"])),
            None,
            None,
        );

        assert!(has_conflict(&reference, "--left", "--right"));
        assert!(has_conflict(&reference, "--alone", "--left"));
        assert!(has_conflict(&reference, "--alone", "--right"));
    }

    #[test]
    fn hidden_conflicts_do_not_enter_the_catalog() {
        let reference = command_reference(
            Command::new("tool")
                .arg(
                    Arg::new("public")
                        .long("public")
                        .help("Public mode")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("internal"),
                )
                .arg(
                    Arg::new("internal")
                        .long("internal")
                        .hide(true)
                        .action(ArgAction::SetTrue),
                ),
            None,
            None,
        );

        assert!(reference.constraints.is_empty());
        assert!(reference
            .options
            .iter()
            .all(|argument| argument.display != "--internal"));
    }

    #[test]
    #[should_panic(expected = "tool argument --undocumented lacks public help")]
    fn a_public_argument_without_help_is_rejected() {
        command_reference(
            Command::new("tool").arg(
                Arg::new("undocumented")
                    .long("undocumented")
                    .action(ArgAction::SetTrue),
            ),
            None,
            None,
        );
    }

    #[test]
    fn supported_cli_constraints_are_published() {
        let catalog = catalog();
        let audit_show = find_command(&catalog.binaries, "evidencectl audit show");
        assert!(audit_show.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredExactlyOne
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

        let evidencectl_new = find_command(&catalog.binaries, "evidencectl new");
        assert!(evidencectl_new.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredExactlyOne
                && constraint.arguments
                    == [
                        "--openapi <OPENAPI>",
                        "--transport <TRANSPORT>",
                        "--starter <STARTER>",
                    ]
        }));
        assert!(evidencectl_new
            .options
            .iter()
            .any(|argument| argument.display == "--profile <PROFILE>" && argument.always_required));

        let source_suggest = find_command(&catalog.binaries, "evidencectl source suggest");
        assert!(source_suggest.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredExactlyOne
                && constraint.arguments == ["--openapi <OPENAPI>", "--project <PROJECT>"]
        }));

        let mock_serve = find_command(&catalog.binaries, "evidencectl source mock serve");
        for option in [
            "--operation <OPERATION>",
            "--seed <SEED>",
            "--as-of <AS_OF>",
            "--explain",
        ] {
            assert!(
                has_conflict(mock_serve, "--config <CONFIG>", option),
                "materialized mock serving did not conflict with {option}"
            );
        }

        let mock_generate = find_command(&catalog.binaries, "evidencectl source mock generate");
        for option in ["--seed <SEED>", "--as-of <AS_OF>"] {
            assert!(
                has_conflict(mock_generate, "--config <CONFIG>", option),
                "stored mock generation did not conflict with {option}"
            );
        }
        for option in [
            "--operation <OPERATION>",
            "--case <CASE>",
            "--path-parameter <PATH_PARAMETERS>",
        ] {
            assert!(
                !has_conflict(mock_generate, "--config <CONFIG>", option),
                "stored mock generation unexpectedly conflicted with {option}"
            );
        }

        let request_prepare = find_command(&catalog.binaries, "evidencectl request prepare");
        assert!(has_conflict(
            request_prepare,
            "--subject <SUBJECT>",
            "--subjects-file <PATH>"
        ));
        assert!(!request_prepare.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::RequiredExactlyOne
                && constraint.arguments == ["--subject <SUBJECT>", "--subjects-file <PATH>"]
        }));

        let dev = find_command(&catalog.binaries, "evidencectl dev");
        assert_eq!(
            dev.usage,
            "evidencectl dev [OPTIONS]\n       evidencectl dev [OPTIONS] <COMMAND>"
        );
        assert!(dev
            .options
            .iter()
            .any(|argument| { argument.display == "--detach" && !argument.always_required }));

        let inspect = find_command(&catalog.binaries, "relayctl inspect");
        assert!(inspect.options.iter().any(|argument| {
            argument.display == "--attribute-column <COLUMN>" && argument.repeatable
        }));

        for (invocation, option) in [
            ("evidence-oid4vci check", "--config <CONFIG>"),
            ("relay serve", "--runtime <RUNTIME>"),
        ] {
            assert!(find_command(&catalog.binaries, invocation)
                .options
                .iter()
                .any(|argument| argument.display == option
                    && argument.environment.is_some()
                    && !argument.always_required));
        }
    }
}
