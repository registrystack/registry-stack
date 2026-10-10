// SPDX-License-Identifier: Apache-2.0
//! Offline contract tests for `bregctl instance-claim`. They prove the
//! refusals an operator meets before any database connection is opened.

use serde_json::Value;

const MISSING_RUNTIME: &str = "/registry/instance-claim-runtime-that-does-not-exist.yaml";

fn run(arguments: &[&str]) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(arguments.iter().copied(), &mut stdout, &mut stderr);
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

fn refusal(arguments: &[&str], code: &str, path: &str, artifact: &str) -> Value {
    let (status, stdout, stderr) = run(arguments);
    assert_eq!(status, 1, "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
    let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
    assert_eq!(report["ok"], false);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], code, "{stdout}");
    assert_eq!(diagnostic["path"], path, "{stdout}");
    assert_eq!(diagnostic["artifact"], artifact, "{stdout}");
    report
}

#[test]
fn adopting_without_acknowledging_the_retired_original_is_refused_before_any_connection() {
    let report = refusal(
        &[
            "bregctl",
            "--format",
            "json",
            "instance-claim",
            "adopt",
            "--runtime-config",
            MISSING_RUNTIME,
        ],
        "instance-claim.acknowledgement.required",
        "acknowledgeOriginalRetired",
        "command-arguments",
    );
    assert_eq!(report["command"], "instance-claim adopt");
}

#[test]
fn a_relative_runtime_configuration_is_refused_for_every_subcommand() {
    for arguments in [
        vec![
            "bregctl",
            "--format",
            "json",
            "instance-claim",
            "status",
            "--runtime-config",
            "runtime.yaml",
        ],
        vec![
            "bregctl",
            "--format",
            "json",
            "instance-claim",
            "adopt",
            "--runtime-config",
            "runtime.yaml",
            "--acknowledge-original-retired",
        ],
    ] {
        refusal(
            &arguments,
            "instance-claim.runtime-config.invalid",
            "runtimeConfig",
            "command-arguments",
        );
    }
}

#[test]
fn an_unreadable_runtime_configuration_reports_the_claim_unavailable() {
    for arguments in [
        vec![
            "bregctl",
            "--format",
            "json",
            "instance-claim",
            "status",
            "--runtime-config",
            MISSING_RUNTIME,
        ],
        vec![
            "bregctl",
            "--format",
            "json",
            "instance-claim",
            "adopt",
            "--runtime-config",
            MISSING_RUNTIME,
            "--acknowledge-original-retired",
        ],
    ] {
        let report = refusal(
            &arguments,
            "instance-claim.unavailable",
            "instanceClaim",
            "instance-claim",
        );
        let text = report.to_string();
        assert!(!text.contains(MISSING_RUNTIME), "path leaked: {text}");
    }
}
