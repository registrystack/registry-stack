// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::io::Write;
use std::process::ExitCode;

use serde_json::Value;

fn run_json<'a>(arguments: impl IntoIterator<Item = &'a OsStr>) -> (ExitCode, Value) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
        ]
        .into_iter()
        .chain(arguments),
        &mut stdout,
        &mut stderr,
    );
    assert!(stderr.is_empty());
    let output = String::from_utf8(stdout).unwrap();
    (status, serde_json::from_str(&output).unwrap())
}

/// A refused runtime file is reported with the shared reader's diagnostics,
/// exactly as `status` reports the same file, and never as the doctor's
/// unusable-binding warning.
#[test]
fn a_refused_runtime_configuration_is_reported_as_status_reports_it() {
    const PATH_CANARY: &str = "external-projection-path-canary";
    const CONFIG_CANARY: &str = "external-projection-config-canary";
    for command in ["inspect", "withdraw", "rotate"] {
        let mut config = tempfile::Builder::new()
            .prefix(PATH_CANARY)
            .tempfile()
            .unwrap();
        writeln!(config, "invalid: [{CONFIG_CANARY}").unwrap();
        let (status, report) = run_json([
            OsStr::new("external-projection"),
            OsStr::new(command),
            OsStr::new("--runtime-config"),
            config.path().as_os_str(),
            OsStr::new("--projection"),
            OsStr::new("holdings-indexed"),
        ]);
        let (status_exit, status_report) = run_json([
            OsStr::new("status"),
            OsStr::new("--runtime-config"),
            config.path().as_os_str(),
        ]);
        let rendered = report.to_string();
        for value in [PATH_CANARY, CONFIG_CANARY] {
            assert!(!rendered.contains(value), "{rendered}");
        }
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], format!("external-projection {command}"));
        assert_eq!(status, status_exit);
        assert_ne!(status, ExitCode::SUCCESS);
        assert!(!report["diagnostics"].as_array().unwrap().is_empty());
        assert_eq!(report["diagnostics"], status_report["diagnostics"]);
        for diagnostic in report["diagnostics"].as_array().unwrap() {
            assert!(
                !diagnostic["code"]
                    .as_str()
                    .unwrap()
                    .starts_with("external-projection."),
                "{rendered}"
            );
            assert_eq!(diagnostic["artifact"], "runtime-configuration");
            assert_eq!(
                diagnostic["suggestedAction"],
                "correct-runtime-configuration"
            );
        }
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
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"],
        "external-projection.runtime-config.path-invalid"
    );
    assert_eq!(diagnostic["path"], "runtimeConfig");
    assert_eq!(diagnostic["artifact"], "runtime-configuration");
    assert_eq!(
        diagnostic["suggestedAction"],
        "correct-runtime-configuration"
    );
}
