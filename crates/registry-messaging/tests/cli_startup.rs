// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn help_and_version_ignore_invalid_operational_log_settings() {
    for value in [
        "",
        "debug",
        "registry_messaging=trace",
        "canary-invalid-log",
    ] {
        for argument in ["--help", "--version"] {
            let output = Command::new(env!("CARGO_BIN_EXE_messaging"))
                .arg(argument)
                .env("MESSAGING_LOG", value)
                .output()
                .expect("run Messaging informational command");
            assert!(output.status.success(), "{value:?} {argument}: {output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("messaging"));
            assert!(output.stderr.is_empty(), "{output:?}");
        }
    }
}

#[test]
fn serve_refuses_invalid_log_settings_before_reading_configuration() {
    for value in [
        "",
        "debug",
        "registry_messaging=trace",
        "canary-invalid-log",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_messaging"))
            .args(["--runtime-config", "/canary-missing/runtime.yaml", "serve"])
            .env("MESSAGING_LOG", value)
            .output()
            .expect("run Messaging serve");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "messaging: MESSAGING_LOG must be one of error, warn, or info\n"
        );
    }
}
