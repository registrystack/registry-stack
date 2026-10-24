//! Every command module is reachable from the binary.
//!
//! The crate has only a `[[bin]]` target, so the other integration tests pull
//! command modules in with `#[path = "../src/..."] mod`. That compiles a module
//! whether or not `main.rs` declares it, which lets a command ship with a full
//! test suite and still be unreachable from `evidencectl`. This file drives the
//! real binary so the top-level surface cannot drift away from `src/`.

use std::process::Command;

/// The complete top-level subcommand set. Adding a command means adding it
/// here; the point of the list is that an omission fails rather than passes.
const TOP_LEVEL_COMMANDS: [&str; 22] = [
    "client",
    "access",
    "keygen",
    "jwks",
    "jwk",
    "init",
    "check",
    "explain",
    "types",
    "test",
    "doctor",
    "target",
    "package",
    "fixtures",
    "source",
    "dev",
    "request",
    "verify",
    "audit",
    "tooling",
    "api",
    "connection",
];

#[test]
fn every_top_level_command_is_listed_and_dispatchable() {
    let help = evidencectl(&["--help"]);
    for command in TOP_LEVEL_COMMANDS {
        assert!(
            help.contains(command),
            "`evidencectl --help` does not list `{command}`:\n{help}"
        );

        // Listing is not dispatch: clap prints help for a declared variant even
        // when the arm behind it is missing, so ask the command itself.
        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args([command, "--help"])
            .output()
            .expect("run evidencectl");
        assert!(
            output.status.success(),
            "`evidencectl {command} --help` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// The complete `tooling` subcommand set, held to the same rule.
const TOOLING_COMMANDS: [&str; 2] = ["editor", "language-server"];

#[test]
fn tooling_lists_and_dispatches_every_subcommand() {
    let help = evidencectl(&["tooling", "--help"]);
    for command in TOOLING_COMMANDS {
        assert!(
            help.contains(command),
            "`evidencectl tooling --help` does not list `{command}`:\n{help}"
        );

        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["tooling", command, "--help"])
            .output()
            .expect("run evidencectl");
        assert!(
            output.status.success(),
            "`evidencectl tooling {command} --help` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn an_undeclared_command_is_still_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["not-a-command", "--help"])
        .output()
        .expect("run evidencectl");
    assert!(
        !output.status.success(),
        "an unknown subcommand must not succeed"
    );
}

#[test]
fn standard_check_option_and_retired_bare_dev_options_are_clear_in_help() {
    let check = evidencectl(&["check", "--help"]);
    assert!(check.contains("--deny-warnings"), "{check}");

    let dev = evidencectl(&["dev", "--help"]);
    assert!(!dev.contains("--detach"), "{dev}");
    assert!(!dev.contains("--project"), "{dev}");
    assert!(dev.contains("start"), "{dev}");
}

#[test]
fn progressive_request_preparation_accepts_no_caller_supplied_selector() {
    registry_evidencectl::command()
        .try_get_matches_from([
            "evidencectl",
            "request",
            "prepare",
            "--profile",
            "client.json",
            "--requirement",
            "authentication-derived-status",
            "--name",
            "authentication-derived-status",
        ])
        .expect("the published contract decides whether request-origin selectors are required");
}

#[test]
fn retired_preserved_context_flag_is_refused_and_explicit_target_is_accepted() {
    for incomplete in [
        vec!["--preserve-target-authenticated-context"],
        vec![
            "--preserve-target-authenticated-context",
            "--target",
            "target",
        ],
        vec![
            "--preserve-target-authenticated-context",
            "--issuer-project",
            "issuer",
        ],
    ] {
        let mut arguments = vec!["evidencectl", "dev", "start", "project"];
        arguments.extend(incomplete);
        assert!(
            registry_evidencectl::command()
                .try_get_matches_from(arguments)
                .is_err(),
            "incomplete preserved-context selection was accepted"
        );
    }
    registry_evidencectl::command()
        .try_get_matches_from([
            "evidencectl",
            "dev",
            "start",
            "project",
            "--target",
            "target",
            "--issuer-project",
            "issuer",
        ])
        .expect("the complete explicit selection is accepted");
}

fn evidencectl(arguments: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("run evidencectl");
    assert!(
        output.status.success(),
        "evidencectl {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}
