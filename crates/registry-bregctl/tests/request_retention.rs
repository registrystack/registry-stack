// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::path::Path;

use serde_json::Value;

const PATH_VALUE_CANARY: &str = "request-retention-runtime-path-value-canary";
const REQUEST_VALUE_CANARY: &str = "request-retention-request-value-canary";

fn run<I, T>(arguments: I) -> (u8, String, String)
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(arguments, &mut stdout, &mut stderr);
    (
        if status == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        },
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

#[test]
fn operator_commands_share_one_value_free_refusal() {
    let relative = Path::new(PATH_VALUE_CANARY);
    let cases = [
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("request-retention"),
            OsStr::new("list"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
        ],
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("request-retention"),
            OsStr::new("dry-run"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--request-entity"),
            OsStr::new(REQUEST_VALUE_CANARY),
            OsStr::new("--request-id"),
            OsStr::new("00000000-0000-4000-8000-000000000001"),
            OsStr::new("--proposal-version"),
            OsStr::new("1"),
        ],
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("request-retention"),
            OsStr::new("erase"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--request-entity"),
            OsStr::new(REQUEST_VALUE_CANARY),
            OsStr::new("--request-id"),
            OsStr::new("00000000-0000-4000-8000-000000000001"),
            OsStr::new("--proposal-version"),
            OsStr::new("1"),
        ],
    ];

    for arguments in cases {
        let (status, stdout, stderr) = run(arguments);
        assert_eq!(status, 1);
        assert!(stderr.is_empty());
        assert!(!stdout.contains(PATH_VALUE_CANARY));
        assert!(!stdout.contains(REQUEST_VALUE_CANARY));
        let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "request_retention.operation.refused"
        );
        assert_eq!(report["diagnostics"][0]["path"], "requestRetention");
        assert_eq!(
            report["diagnostics"][0]["artifact"],
            "request_retention_operation"
        );
        assert_eq!(
            report["diagnostics"][0]["suggestedAction"],
            "verify_request_retention_operation"
        );
    }
}

#[test]
fn request_retention_help_describes_bounded_exact_operator_contract() {
    let (status, stdout, stderr) = run(["bregctl", "request-retention", "dry-run", "--help"]);

    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    assert!(stdout.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(stdout.contains("--request-entity <ENTITY>"));
    assert!(stdout.contains("--request-id <UUID>"));
    assert!(stdout.contains("--proposal-version <VERSION>"));
}
