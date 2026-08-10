// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

fn relayctl(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_relayctl"))
        .args(arguments)
        .output()
        .expect("relayctl starts")
}

#[test]
fn the_adopter_workflow_is_exposed_by_one_binary() {
    for command in [
        "init", "inspect", "check", "generate", "test", "diff", "package",
    ] {
        let output = relayctl(&[command, "--help"]);
        assert!(output.status.success(), "{command} help failed");
        assert!(output.stderr.is_empty(), "{command} help used stderr");
    }
}

#[test]
fn schema_inspection_offers_no_row_or_value_sampling_surface() {
    let output = relayctl(&["inspect", "--help"]);
    assert!(output.status.success());

    let help = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(help.contains("without reading row values"));
    assert!(help.contains("--profile <PROFILE>"));
    assert!(help.contains("live-read-only"));
    assert!(help.contains("snapshot"));
    for forbidden in ["--sample", "--rows", "--values", "--limit"] {
        assert!(!help.contains(forbidden), "unexpected option {forbidden}");
    }
}

#[test]
fn package_refuses_an_implicit_destination_without_echoing_project_contents() {
    let output = relayctl(&["package", "project"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    let error = String::from_utf8(output.stderr).expect("error is UTF-8");
    assert!(error.contains("--output"));
    assert!(!error.contains("selector"));
    assert!(!error.contains("record"));
}

#[test]
fn adopter_commands_link_the_shared_library_and_never_spawn_relay() {
    let library = include_str!("../src/lib.rs");
    let shared = include_str!("../src/shared.rs");
    let binary = include_str!("../src/main.rs");
    let production = format!("{library}\n{shared}\n{binary}");

    assert!(shared.contains("registry_relay_v2::tooling"));
    for forbidden in ["std::process::Command", "Command::new", "rusqlite"] {
        assert!(
            !production.contains(forbidden),
            "tooling boundary contains {forbidden}"
        );
    }
}
