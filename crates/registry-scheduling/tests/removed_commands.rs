// SPDX-License-Identifier: Apache-2.0

//! The removed `scheduling migrate` subcommand refuses with a usage exit and
//! names the commands that replace it, with or without `--runtime-config`.

use std::process::Command;

fn scheduling(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_scheduling"))
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("run scheduling")
}

#[test]
fn scheduling_migrate_refuses_and_names_plan_then_apply() {
    for args in [
        &["migrate"][..],
        &["--runtime-config", "/nonexistent/runtime.yaml", "migrate"],
        &["--runtime-config=/nonexistent/runtime.yaml", "migrate"],
    ] {
        let output = scheduling(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(
            stderr.starts_with("scheduling: `scheduling migrate` is removed"),
            "{stderr}"
        );
        assert!(stderr.contains(
            "run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"
        ));
        assert!(
            !stderr.contains("/nonexistent"),
            "the refusal reads no configuration"
        );
    }
}

#[test]
fn serve_without_a_runtime_config_is_still_a_usage_error() {
    let output = scheduling(&["serve"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("--runtime-config"), "{stderr}");
}
