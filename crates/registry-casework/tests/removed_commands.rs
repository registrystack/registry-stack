//! The removed `casework migrate` subcommand refuses with a usage exit and
//! names the commands that replace it.

use std::process::Command;

fn casework(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_casework"))
        .args(args)
        .env_remove("CASEWORK_LOG")
        .output()
        .expect("run casework")
}

#[test]
fn casework_migrate_refuses_and_names_plan_then_apply() {
    for args in [
        &["migrate"][..],
        &["--runtime-config", "/nonexistent/runtime.yaml", "migrate"],
    ] {
        let output = casework(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(
            stderr.starts_with("casework: casework migrate was removed"),
            "{stderr}"
        );
        assert!(stderr.contains(
            "run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`"
        ));
        assert!(
            !stderr.contains("/nonexistent"),
            "the refusal reads no configuration"
        );
    }
}
