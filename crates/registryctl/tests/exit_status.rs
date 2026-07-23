use std::process::Command;

fn run_registryctl(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args(args)
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .expect("registryctl runs")
}

#[test]
fn success_uses_exit_status_zero() {
    let output = run_registryctl(&["--version"]);

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn command_failure_uses_exit_status_one() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .arg("restart")
        .current_dir(temporary.path())
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .expect("registryctl runs");

    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn usage_failure_uses_exit_status_two() {
    let output = run_registryctl(&["not-a-command"]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn removed_spreadsheet_alias_is_a_usage_failure() {
    let output = run_registryctl(&["init", "spreadsheet-api", "project"]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn missing_init_mode_is_a_usage_failure() {
    let output = run_registryctl(&["init"]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn conflicting_init_modes_are_a_usage_failure() {
    let output = run_registryctl(&["init", "--from", "http", "relay", "project"]);

    assert_eq!(output.status.code(), Some(2));
}
