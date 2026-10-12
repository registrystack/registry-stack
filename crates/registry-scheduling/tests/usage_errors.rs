// SPDX-License-Identifier: Apache-2.0

//! `scheduling` has one command, `serve`. Any other command line is a usage
//! error the argument parser reports with exit 2 before any configuration is
//! read.

use std::process::Command;

fn scheduling(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_scheduling"))
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("run scheduling")
}

#[test]
fn a_command_other_than_serve_is_a_usage_error_that_reads_no_configuration() {
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
            stderr.starts_with("error: unrecognized subcommand 'migrate'"),
            "{stderr}"
        );
        assert!(stderr.contains("Usage: scheduling"), "{stderr}");
        assert!(
            !stderr.contains("/nonexistent"),
            "a usage error reads no configuration"
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
