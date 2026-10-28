// SPDX-License-Identifier: Apache-2.0
//! Offline command-contract tests for `bregctl timer`.

fn run(arguments: &[&str]) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(arguments.iter().copied(), &mut stdout, &mut stderr);
    (
        if status == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        },
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

fn help(arguments: &[&str]) -> String {
    let (status, stdout, stderr) = run(arguments);
    assert_eq!(status, 0, "{arguments:?}: {stdout}{stderr}");
    assert!(stderr.is_empty(), "{arguments:?}: {stderr}");
    stdout
}

#[test]
fn timer_help_exposes_only_the_bounded_operator_commands() {
    let rendered = help(&["bregctl", "timer", "--help"]);
    for subcommand in ["status", "list", "show", "retry", "pause", "resume"] {
        assert!(
            rendered
                .lines()
                .any(|line| line.trim_start().starts_with(subcommand)),
            "{subcommand}: {rendered}"
        );
    }
    for unsupported in ["force-run", "run-now", "retention"] {
        assert!(!rendered.contains(unsupported), "{unsupported}: {rendered}");
    }
}

#[test]
fn timer_read_command_help_names_the_bounded_selection_contract() {
    let status = help(&["bregctl", "timer", "status", "--help"]);
    assert!(
        status.contains("--runtime-config <ABSOLUTE_FILE>"),
        "{status}"
    );

    let list = help(&["bregctl", "timer", "list", "--help"]);
    for flag in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--state <STATE>",
        "--record-type <ID>",
        "--timer <ID>",
        "--after-cursor <CURSOR>",
        "--limit <COUNT>",
    ] {
        assert!(list.contains(flag), "{flag}: {list}");
    }
    for unsupported in ["--record-id", "--payload"] {
        assert!(!list.contains(unsupported), "{unsupported}: {list}");
    }

    let show = help(&["bregctl", "timer", "show", "--help"]);
    for flag in ["--runtime-config <ABSOLUTE_FILE>", "--occurrence-id <UUID>"] {
        assert!(show.contains(flag), "{flag}: {show}");
    }
}

#[test]
fn timer_mutation_help_requires_exact_epochs_and_audit_inputs() {
    let retry = help(&["bregctl", "timer", "retry", "--help"]);
    for flag in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--occurrence-id <UUID>",
        "--expected-attempt-count <COUNT>",
        "--operator-reference <REFERENCE>",
        "--reason <TEXT>",
    ] {
        assert!(retry.contains(flag), "{flag}: {retry}");
    }

    for command in ["pause", "resume"] {
        let rendered = help(&["bregctl", "timer", command, "--help"]);
        for flag in [
            "--runtime-config <ABSOLUTE_FILE>",
            "--expected-control-epoch <EPOCH>",
            "--operator-reference <REFERENCE>",
            "--reason <TEXT>",
        ] {
            assert!(rendered.contains(flag), "{command} {flag}: {rendered}");
        }
    }
}
