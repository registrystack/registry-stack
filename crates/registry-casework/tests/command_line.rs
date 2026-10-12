//! `casework` has one subcommand, `serve`. Database changes are applied with
//! `caseworkctl plan` then `caseworkctl apply`, so `migrate` is refused by the
//! argument parser as any word it does not know.

use std::process::Command;

fn casework(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_casework"))
        .args(args)
        .env_remove("CASEWORK_LOG")
        .output()
        .expect("run casework")
}

fn usage_error(args: &[&str]) -> String {
    let output = casework(args);
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    assert!(output.stdout.is_empty(), "{args:?}");
    String::from_utf8(output.stderr).expect("UTF-8 stderr")
}

#[test]
fn casework_migrate_is_refused_as_an_unrecognized_subcommand() {
    for args in [
        &["migrate"][..],
        &["--runtime-config", "/nonexistent/runtime.yaml", "migrate"],
        &[
            "--runtime-config",
            "/nonexistent/runtime.yaml",
            "migrate",
            "--now",
        ],
    ] {
        let stderr = usage_error(args);
        assert!(
            stderr.starts_with("error: unrecognized subcommand 'migrate'"),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains("Usage: casework"), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("/nonexistent"),
            "the refusal reads no configuration"
        );
        let unknown: Vec<&str> = args
            .iter()
            .map(|arg| {
                if *arg == "migrate" {
                    "not-a-command"
                } else {
                    arg
                }
            })
            .collect();
        assert_eq!(
            stderr.replace("migrate", "not-a-command"),
            usage_error(&unknown),
            "{args:?}"
        );
    }
}
