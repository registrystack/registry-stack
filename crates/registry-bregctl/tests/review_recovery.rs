// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::path::Path;

use serde_json::Value;

const PATH_VALUE_CANARY: &str = "review-recovery-runtime-path-value-canary";
const REQUEST_VALUE_CANARY: &str = "review-recovery-request-value-canary";

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
fn review_recovery_commands_share_one_value_free_refusal() {
    let relative = Path::new(PATH_VALUE_CANARY);
    for operation in ["resubmit", "close", "retry-application"] {
        let (status, stdout, stderr) = run([
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("review-recovery"),
            OsStr::new(operation),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--request-entity"),
            OsStr::new(REQUEST_VALUE_CANARY),
            OsStr::new("--request-id"),
            OsStr::new("00000000-0000-4000-8000-000000000001"),
            OsStr::new("--proposal-version"),
            OsStr::new("1"),
        ]);
        assert_eq!(status, 1);
        assert!(stderr.is_empty());
        assert!(!stdout.contains(PATH_VALUE_CANARY));
        assert!(!stdout.contains(REQUEST_VALUE_CANARY));
        let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
        assert_eq!(report["command"], format!("review-recovery {operation}"));
        assert_eq!(
            report["diagnostics"][0]["code"],
            "review-recovery.operation.refused"
        );
        assert_eq!(report["diagnostics"][0]["path"], "reviewRecovery");
        assert_eq!(
            report["diagnostics"][0]["artifact"],
            "review-recovery-operation"
        );
        assert_eq!(
            report["diagnostics"][0]["suggestedAction"],
            "verify-review-recovery-operation"
        );
    }
}

#[test]
fn review_recovery_help_describes_the_exact_operator_contract() {
    for operation in ["resubmit", "close", "retry-application"] {
        let (status, stdout, stderr) = run(["bregctl", "review-recovery", operation, "--help"]);

        assert_eq!(status, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("--runtime-config <ABSOLUTE_FILE>"));
        assert!(stdout.contains("--request-entity <ENTITY>"));
        assert!(stdout.contains("--request-id <UUID>"));
        assert!(stdout.contains("--proposal-version <VERSION>"));
    }
}
