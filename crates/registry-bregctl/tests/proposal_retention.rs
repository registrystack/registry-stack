// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::path::Path;

use serde_json::Value;

const PATH_VALUE_CANARY: &str = "proposal-retention-runtime-path-value-canary";
const REQUEST_VALUE_CANARY: &str = "proposal-retention-request-value-canary";

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
            OsStr::new("proposal-retention"),
            OsStr::new("list"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
        ],
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("proposal-retention"),
            OsStr::new("dry-run"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--action-id"),
            OsStr::new(REQUEST_VALUE_CANARY),
            OsStr::new("--proposal-id"),
            OsStr::new("00000000-0000-4000-8000-000000000001"),
            OsStr::new("--submission-version"),
            OsStr::new("1"),
        ],
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("proposal-retention"),
            OsStr::new("erase"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--action-id"),
            OsStr::new(REQUEST_VALUE_CANARY),
            OsStr::new("--proposal-id"),
            OsStr::new("00000000-0000-4000-8000-000000000001"),
            OsStr::new("--submission-version"),
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
            "proposal-retention.operation.refused"
        );
        assert_eq!(report["diagnostics"][0]["path"], "proposalRetention");
        assert_eq!(
            report["diagnostics"][0]["artifact"],
            "proposal-retention-operation"
        );
        assert_eq!(
            report["diagnostics"][0]["suggestedAction"],
            "verify-proposal-retention-operation"
        );
    }
}

#[test]
fn proposal_retention_help_describes_bounded_exact_operator_contract() {
    let (status, stdout, stderr) = run(["bregctl", "proposal-retention", "dry-run", "--help"]);

    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    assert!(stdout.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(stdout.contains("--action-id <ACTION>"));
    assert!(stdout.contains("--proposal-id <UUID>"));
    assert!(stdout.contains("--submission-version <VERSION>"));
}
