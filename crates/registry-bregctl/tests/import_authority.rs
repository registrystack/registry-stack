// SPDX-License-Identifier: Apache-2.0
//! Offline contract tests for `bregctl import-authority`. They prove the
//! refusals an operator meets before any database connection is opened, and
//! that no refusal repeats an operator reference, a reason, or a path.

use serde_json::Value;

const MISSING_RUNTIME: &str = "/registry/import-authority-runtime-that-does-not-exist.yaml";
const OPERATOR_CANARY: &str = "import-authority-operator-canary";
const REASON_CANARY: &str = "import-authority-reason-canary";
const PATH_CANARY: &str = "import-authority-path-canary";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const AUTHORITY_ID: &str = "00000000-0000-4000-8000-000000000001";

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

fn open(runtime_config: &str, extra: &[&str]) -> Vec<String> {
    let mut arguments = vec![
        "bregctl",
        "--format",
        "json",
        "import-authority",
        "open",
        "--runtime-config",
        runtime_config,
        "--entity",
        "widget",
        "--profile",
        "loader",
        "--max-items",
        "10",
        "--operator-reference",
        OPERATOR_CANARY,
        "--reason",
        REASON_CANARY,
    ];
    arguments.extend_from_slice(extra);
    arguments.into_iter().map(str::to_owned).collect()
}

fn refusal(arguments: &[String], code: &str, path: &str) -> Value {
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let (status, stdout, stderr) = run(&arguments);
    assert_eq!(status, 1, "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
    for canary in [OPERATOR_CANARY, REASON_CANARY, PATH_CANARY, MISSING_RUNTIME] {
        assert!(!stdout.contains(canary), "{canary} leaked: {stdout}");
    }
    let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
    assert_eq!(report["ok"], false);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], code, "{stdout}");
    assert_eq!(diagnostic["path"], path, "{stdout}");
    assert_eq!(diagnostic["artifact"], "import-authority");
    report
}

#[test]
fn a_relative_runtime_configuration_is_refused_for_every_subcommand() {
    let cases = [
        open(PATH_CANARY, &[]),
        [
            "bregctl",
            "--format",
            "json",
            "import-authority",
            "close",
            "--runtime-config",
            PATH_CANARY,
            "--authority-id",
            AUTHORITY_ID,
            "--operator-reference",
            OPERATOR_CANARY,
            "--reason",
            REASON_CANARY,
        ]
        .map(str::to_owned)
        .to_vec(),
        [
            "bregctl",
            "--format",
            "json",
            "import-authority",
            "close-expired",
            "--runtime-config",
            PATH_CANARY,
        ]
        .map(str::to_owned)
        .to_vec(),
        [
            "bregctl",
            "--format",
            "json",
            "import-authority",
            "list",
            "--runtime-config",
            PATH_CANARY,
        ]
        .map(str::to_owned)
        .to_vec(),
    ];
    for arguments in cases {
        refusal(
            &arguments,
            "import-authority.runtime-config.invalid",
            "runtimeConfig",
        );
    }
}

#[test]
fn an_expiry_outside_one_minute_to_thirty_days_is_refused_before_any_dependency() {
    for expires_in in ["31d", "0d", "0m", "721h", "7", "7x", "d", "1.5d", "+1d", ""] {
        refusal(
            &open(MISSING_RUNTIME, &["--expires-in", expires_in]),
            "import-authority.expires-in.invalid",
            "expiresIn",
        );
    }
}

#[test]
fn the_window_bounds_themselves_are_accepted() {
    // Each bound passes the offline checks and reaches the runtime
    // configuration, which does not exist, so the refusal names it instead.
    for expires_in in ["30d", "720h", "1m", "7d"] {
        refusal(
            &open(MISSING_RUNTIME, &["--expires-in", expires_in]),
            "import-authority.unavailable",
            "importAuthority",
        );
    }
}

#[test]
fn a_malformed_or_repeated_pinned_digest_is_refused_before_any_dependency() {
    let upper = DIGEST.to_uppercase();
    let short = &DIGEST[..63];
    for digests in [
        vec!["--input-sha256", upper.as_str()],
        vec!["--input-sha256", short],
        vec!["--input-sha256", DIGEST, "--input-sha256", DIGEST],
    ] {
        refusal(
            &open(MISSING_RUNTIME, &digests),
            "import-authority.request.invalid",
            "importAuthority",
        );
    }
}

#[test]
fn an_empty_reason_or_a_volume_below_one_is_refused_before_any_dependency() {
    let mut empty_reason = open(MISSING_RUNTIME, &[]);
    let at = empty_reason
        .iter()
        .position(|argument| argument == REASON_CANARY)
        .expect("reason argument");
    empty_reason[at] = String::new();
    refusal(
        &empty_reason,
        "import-authority.request.invalid",
        "importAuthority",
    );

    let mut zero = open(MISSING_RUNTIME, &[]);
    let at = zero
        .iter()
        .position(|argument| argument == "10")
        .expect("max-items argument");
    zero[at] = "0".to_owned();
    refusal(&zero, "import-authority.request.invalid", "importAuthority");
}

#[test]
fn close_refuses_an_authority_identifier_that_is_not_a_uuid() {
    let arguments = [
        "bregctl",
        "--format",
        "json",
        "import-authority",
        "close",
        "--runtime-config",
        MISSING_RUNTIME,
        "--authority-id",
        PATH_CANARY,
        "--operator-reference",
        OPERATOR_CANARY,
        "--reason",
        REASON_CANARY,
    ]
    .map(str::to_owned);
    refusal(
        &arguments,
        "import-authority.authority-id.invalid",
        "authorityId",
    );
}

#[test]
fn an_unavailable_runtime_configuration_is_one_value_free_refusal() {
    refusal(
        &open(MISSING_RUNTIME, &["--input-sha256", DIGEST]),
        "import-authority.unavailable",
        "importAuthority",
    );
    for subcommand in ["close-expired", "list"] {
        let arguments = [
            "bregctl",
            "--format",
            "json",
            "import-authority",
            subcommand,
            "--runtime-config",
            MISSING_RUNTIME,
        ]
        .map(str::to_owned);
        refusal(
            &arguments,
            "import-authority.unavailable",
            "importAuthority",
        );
    }
}

#[test]
fn import_authority_help_describes_the_operator_contract() {
    let (status, stdout, stderr) = run(&["bregctl", "import-authority", "--help"]);
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    for subcommand in ["open", "close", "close-expired", "list"] {
        assert!(
            stdout
                .lines()
                .any(|line| line.trim_start().starts_with(subcommand)),
            "{subcommand}: {stdout}"
        );
    }

    let (status, stdout, stderr) = run(&["bregctl", "import-authority", "open", "--help"]);
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    for flag in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--entity <ENTITY>",
        "--profile <PROFILE>",
        "--max-items <COUNT>",
        "--expires-in <DURATION>",
        "[default: 7d]",
        "--input-sha256 <SHA256>",
        "--operator-reference <REFERENCE>",
        "--reason <TEXT>",
    ] {
        assert!(stdout.contains(flag), "{flag}: {stdout}");
    }

    let (status, stdout, stderr) = run(&["bregctl", "import-authority", "close", "--help"]);
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    for flag in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--authority-id <UUID>",
        "--operator-reference <REFERENCE>",
        "--reason <TEXT>",
    ] {
        assert!(stdout.contains(flag), "{flag}: {stdout}");
    }
}
