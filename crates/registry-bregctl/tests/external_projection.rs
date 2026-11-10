// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::io::Write;

use serde_json::Value;

#[test]
fn invalid_runtime_configuration_reports_external_projection_recovery_without_values() {
    const PATH_CANARY: &str = "external-projection-path-canary";
    const CONFIG_CANARY: &str = "external-projection-config-canary";
    for command in ["inspect", "withdraw", "rotate"] {
        let mut config = tempfile::Builder::new()
            .prefix(PATH_CANARY)
            .tempfile()
            .unwrap();
        writeln!(config, "invalid: [{CONFIG_CANARY}").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = registry_bregctl::run_from(
            [
                OsStr::new("bregctl"),
                OsStr::new("--format"),
                OsStr::new("json"),
                OsStr::new("external-projection"),
                OsStr::new(command),
                OsStr::new("--runtime-config"),
                config.path().as_os_str(),
                OsStr::new("--projection"),
                OsStr::new("holdings-indexed"),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_ne!(status, std::process::ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        let output = String::from_utf8(stdout).unwrap();
        for value in [PATH_CANARY, CONFIG_CANARY] {
            assert!(!output.contains(value));
        }
        let report: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], format!("external-projection {command}"));
        assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["code"], "external-projection.unavailable");
        assert_eq!(diagnostic["path"], "externalProjection");
        assert_eq!(diagnostic["artifact"], "external-projection-operation");
        assert_eq!(
            diagnostic["suggestedAction"],
            "verify-external-projection-operation"
        );
    }
}

#[test]
fn a_relative_runtime_configuration_is_refused_before_it_is_read() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            "bregctl",
            "--format",
            "json",
            "external-projection",
            "inspect",
            "--runtime-config",
            "relative/runtime.yaml",
            "--projection",
            "holdings-indexed",
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_ne!(status, std::process::ExitCode::SUCCESS);
    let output = String::from_utf8(stdout).unwrap();
    assert!(!output.contains("relative/runtime.yaml"));
    let report: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "external-projection inspect");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "external-projection.unavailable"
    );
}
