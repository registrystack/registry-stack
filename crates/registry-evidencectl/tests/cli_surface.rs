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
const TOP_LEVEL_COMMANDS: [&str; 21] = [
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
    "request",
    "verify",
    "runtime",
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
const TOOLING_COMMANDS: [&str; 1] = ["editor"];

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
fn retired_language_server_is_refused() {
    let help = evidencectl(&["tooling", "--help"]);
    assert!(!help.contains("language-server"), "{help}");

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["tooling", "language-server"])
        .output()
        .expect("run evidencectl");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("error[evidencectl.usage]"),
        "retired tooling command did not use the standard usage refusal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn access_client_add_is_not_a_command() {
    let access = evidencectl(&["access", "--help"]);
    assert!(access.contains("profile"), "{access}");
    assert!(!access.contains("client"), "{access}");

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["access", "client", "add", "--help"])
        .output()
        .expect("run evidencectl");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("error[evidencectl.usage]"),
        "removed access verb did not use the standard usage refusal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dev_is_not_a_command() {
    assert_usage_refusal(&["dev", "--help"]);
    assert_usage_refusal(&["dev", "start", "--help"]);
    assert!(!evidencectl(&["--help"]).contains("\n  dev "));
}

#[test]
fn source_add_is_not_a_command() {
    let source = evidencectl(&["source", "--help"]);
    assert!(!source.contains("\n  add "), "{source}");
    assert_usage_refusal(&["source", "add", "--help"]);
}

#[test]
fn audit_show_is_not_a_command() {
    let help = evidencectl(&["--help"]);
    assert!(!help.contains("audit"), "{help}");

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["audit", "show", "--help"])
        .output()
        .expect("run evidencectl");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("error[evidencectl.usage]"),
        "removed audit verb did not use the standard usage refusal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
fn standard_check_option_is_clear_in_help() {
    let check = evidencectl(&["check", "--help"]);
    assert!(check.contains("--deny-warnings"), "{check}");
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

fn assert_usage_refusal(arguments: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("run evidencectl");
    assert_eq!(output.status.code(), Some(2), "{arguments:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("error[evidencectl.usage]"),
        "{arguments:?} did not use the standard usage refusal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn posture_conflict_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args([
            "--format",
            "json",
            "check",
            ".",
            "--target",
            "target.yaml",
            "--production",
            "--posture",
            "development",
        ])
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .expect("run evidencectl");
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "usage-error");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "platform.posture.conflict");
    assert_eq!(
        diagnostic["message"],
        "--production and --posture development contradict each other"
    );
    assert_eq!(diagnostic["suggestedAction"], "Use one of them.");
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
