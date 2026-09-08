// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::io::Write;

use serde_json::Value;

#[test]
fn invalid_runtime_configuration_reports_evidence_retention_recovery_without_values() {
    const PATH_CANARY: &str = "evidence-retention-path-canary";
    const CONFIG_CANARY: &str = "evidence-retention-config-canary";
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
            OsStr::new("evidence-retention"),
            OsStr::new("erase-expired"),
            OsStr::new("--runtime-config"),
            config.path().as_os_str(),
            OsStr::new("--before"),
            OsStr::new("2020-01-01T00:00:00Z"),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_ne!(status, std::process::ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let output = String::from_utf8(stdout).unwrap();
    for value in [PATH_CANARY, CONFIG_CANARY, "request_retention"] {
        assert!(!output.contains(value));
    }
    let report: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "evidence-retention erase-expired");
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "evidence_retention.unavailable");
    assert_eq!(diagnostic["path"], "evidenceRetention");
    assert_eq!(diagnostic["artifact"], "evidence_retention_operation");
    assert_eq!(
        diagnostic["suggestedAction"],
        "verify_evidence_retention_operation"
    );
}
