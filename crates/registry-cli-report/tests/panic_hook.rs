// SPDX-License-Identifier: Apache-2.0

use registry_cli_report::{install_panic_hook, Identity};
use serde_json::Value;
use std::process::Command;

const IDENTITY: Identity = Identity {
    binary: "examplectl",
    api_version: "format/v1",
    kind: "ExampleCtlReport",
    version: "1.0.0-dev",
};

fn main() {
    if std::env::var_os("REGISTRY_CLI_REPORT_TEST_PANIC").is_some() {
        let json = std::env::args().any(|arg| arg == "--json");
        install_panic_hook(IDENTITY, json);
        panic!("private-sentinel-that-must-not-escape");
    }
    for json in [true, false] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.env("REGISTRY_CLI_REPORT_TEST_PANIC", "1");
        if json {
            child.arg("--json");
        }
        let output = child.output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stdout.contains("private-sentinel"));
        assert!(!stderr.contains("private-sentinel"));
        if json {
            assert!(stderr.is_empty(), "{stderr}");
            let report: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(report["status"], "operational-failure");
            assert_eq!(
                report["diagnostics"][0]["code"],
                "examplectl.internal-error"
            );
            assert_eq!(report["version"], "1.0.0-dev");
        } else {
            assert!(stdout.is_empty());
            assert!(stderr.contains("examplectl.internal-error"));
            assert!(stderr.contains("next:"));
        }
    }
}
