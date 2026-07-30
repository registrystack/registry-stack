use std::fs;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args(args)
        .env_remove("REGISTRYCTL_ENVIRONMENT")
        .output()
        .expect("registryctl runs")
}

#[test]
fn status_zero_means_the_requested_operation_completed() {
    assert_eq!(run(&["--version"]).status.code(), Some(0));
    assert_eq!(run(&["--help"]).status.code(), Some(0));
    assert_eq!(run(&["deploy"]).status.code(), Some(0));
}

#[test]
fn status_one_means_a_negative_domain_result() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::write(
        temporary.path().join("registry-stack.yaml"),
        "registry: [not valid for this project\n",
    )
    .expect("invalid project fixture writes");
    fs::create_dir(temporary.path().join("environments")).expect("environment directory writes");
    fs::write(
        temporary.path().join("environments/local.yaml"),
        "version: 1\n",
    )
    .expect("environment fixture writes");

    let output = run(&[
        "-C",
        temporary.path().to_str().expect("temporary path is UTF-8"),
        "check",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn status_two_means_invalid_usage_or_a_removed_surface() {
    for args in [
        &["not-a-command"][..],
        &["start"][..],
        &["test", "--live"][..],
        &["check", "--format", "yaml"][..],
        &["init", "project-without-template"][..],
    ] {
        assert_eq!(
            run(args).status.code(),
            Some(2),
            "expected usage status for {args:?}"
        );
    }
}

#[test]
fn status_three_means_an_operational_dependency_failed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let missing = temporary.path().join("missing-project");
    let output = run(&[
        "-C",
        missing.to_str().expect("temporary path is UTF-8"),
        "check",
    ]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dev_lifecycle_queries_do_not_create_a_runtime() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    let project_argument = project.to_str().expect("temporary path is UTF-8");
    let initialized = run(&["init", project_argument, "--template", "http"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let output = run(&["-C", project_argument, "dev", "status"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        !project.join(".registry-stack/dev").exists(),
        "dev status generated runtime state"
    );
    assert!(
        !project.join(".registry-stack/dev-artifacts").exists(),
        "dev status generated signed artifacts or credentials"
    );
}
