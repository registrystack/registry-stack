// SPDX-License-Identifier: Apache-2.0

//! Conformance gate for the `messagingctl --format json` report envelope.

use super::*;
use std::path::Path;

fn invoke(arguments: impl IntoIterator<Item = OsString>) -> (ExitCode, Value) {
    let mut args = vec![
        OsString::from("messagingctl"),
        OsString::from("--format=json"),
    ];
    args.extend(arguments);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = main_entry_from(args, &mut stdout, &mut stderr);
    assert!(
        stderr.is_empty(),
        "JSON command wrote stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let report = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
        panic!(
            "command stdout is JSON: {error}: {}",
            String::from_utf8_lossy(&stdout)
        )
    });
    assert_envelope(&stdout, &report, exit);
    (exit, report)
}

/// Every JSON report opens with `ok`, `command`, and `status` in that order;
/// `ok` is true exactly when the process exits zero, and a report that is not
/// ok carries at least one diagnostic naming the next step.
fn assert_envelope(stdout: &[u8], report: &Value, exit: ExitCode) {
    let text = String::from_utf8_lossy(stdout);
    let head = text
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once('"').map(|(key, _)| key))
        .take(3)
        .collect::<Vec<_>>();
    assert_eq!(head, ["ok", "command", "status"], "{text}");
    assert_eq!(report["ok"], json!(exit == ExitCode::SUCCESS), "{text}");
    if exit != ExitCode::SUCCESS {
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        assert!(!diagnostics.is_empty(), "{text}");
        for diagnostic in diagnostics {
            assert_eq!(diagnostic["severity"], "error", "{text}");
            // The empty pointer names the document's root (CFG-DIAG-1).
            assert!(diagnostic["path"].is_string(), "path: {text}");
            for member in ["code", "artifact", "message", "suggestedAction"] {
                assert!(
                    diagnostic[member]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "{member}: {text}"
                );
            }
        }
    }
}

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn path_arguments(values: &[&str], path: &Path) -> Vec<OsString> {
    let mut all = arguments(values);
    all.push(path.as_os_str().to_owned());
    all
}

/// A temporary directory by its canonical path, which the runtime
/// configuration loader requires.
fn workspace() -> (tempfile::TempDir, PathBuf) {
    let guard = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(guard.path()).unwrap();
    (guard, root)
}

/// A starter authoring project and a template data file its sample accepts.
fn starter(root: &Path) -> (PathBuf, PathBuf) {
    let project = root.join("starter");
    let (exit, report) = invoke(path_arguments(&["init"], &project));
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let data = root.join("data.json");
    std::fs::write(
        &data,
        br#"{"name": "Ada", "day": "2026-10-01", "office": "Central"}"#,
    )
    .unwrap();
    (project, data)
}

/// The arguments of every database command, pointed at a runtime
/// configuration that does not exist, so each one fails before any database.
fn database_commands(missing: &Path) -> Vec<(&'static str, Vec<OsString>)> {
    let id = "0b0b8f1c-7a7e-4c43-9d7e-0f3c5d9a1e2b";
    let with_config = |values: &[&str]| {
        let mut all = arguments(values);
        all.push(OsString::from("--runtime-config"));
        all.push(missing.as_os_str().to_owned());
        all
    };
    vec![
        ("apply", with_config(&["apply"])),
        ("messages list", with_config(&["messages", "list"])),
        ("messages show", with_config(&["messages", "show", id])),
        ("messages retry", with_config(&["messages", "retry", id])),
        (
            "messages settle",
            with_config(&["messages", "settle", id, "--outcome", "sent"]),
        ),
        ("messages cancel", with_config(&["messages", "cancel", id])),
        (
            "retention erase-expired",
            with_config(&[
                "retention",
                "erase-expired",
                "--before",
                "2026-01-01T00:00:00Z",
            ]),
        ),
    ]
}

#[test]
fn every_public_json_report_opens_with_the_envelope() {
    let (_guard, root) = workspace();
    let (project, data) = starter(&root);
    let missing = root.join("missing.yaml");

    let mut runs = vec![
        path_arguments(&["init"], &project),
        path_arguments(&["check", "--project"], &project),
        path_arguments(&["check", "--runtime-config"], &missing),
        {
            let mut all = path_arguments(&["package"], &project);
            all.push(OsString::from("--output"));
            all.push(root.join("installed").into_os_string());
            all.push(OsString::from("--dry-run"));
            all
        },
        {
            let mut all = path_arguments(&["package"], &project);
            all.push(OsString::from("--output"));
            all.push(project.clone().into_os_string());
            all
        },
        {
            let mut all = path_arguments(&["preview", "--project"], &project);
            all.extend(arguments(&["appointment-reminder", "1", "--locale", "de"]));
            all.push(OsString::from("--data"));
            all.push(data.clone().into_os_string());
            all
        },
        path_arguments(&["dev"], &root.join("absent")),
        {
            let mut all = arguments(&["dev", "token", "client"]);
            all.push(root.join("absent").into_os_string());
            all
        },
        arguments(&["--not-a-real-argument"]),
        arguments(&["check"]),
    ];
    runs.extend(
        database_commands(&missing)
            .into_iter()
            .map(|(_, arguments)| arguments),
    );
    for arguments in runs {
        // `invoke` holds each report to the envelope.
        let (_, report) = invoke(arguments);
        assert!(report["command"].is_string(), "{report}");
    }
}

/// A successful preview prints the exact bytes the runtime's preview route
/// answers, so it is the one success without the envelope; its refusal
/// carries the envelope like every other failure.
#[test]
fn a_successful_preview_is_the_route_body_and_its_refusal_is_enveloped() {
    let (_guard, root) = workspace();
    let (project, data) = starter(&root);
    let run = |locale: &str| {
        let mut args = vec![
            OsString::from("messagingctl"),
            OsString::from("--format=json"),
        ];
        args.extend(path_arguments(&["preview", "--project"], &project));
        args.extend(arguments(&[
            "appointment-reminder",
            "1",
            "--locale",
            locale,
        ]));
        args.push(OsString::from("--data"));
        args.push(data.clone().into_os_string());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(args, &mut stdout, &mut stderr);
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
        (exit, stdout)
    };
    let (exit, stdout) = run("en");
    assert_eq!(exit, ExitCode::SUCCESS);
    let body: Value = serde_json::from_slice(&stdout).unwrap();
    assert!(body.get("ok").is_none(), "{body}");
    assert!(body.get("command").is_none(), "{body}");

    let (exit, stdout) = run("de");
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
    let report: Value = serde_json::from_slice(&stdout).unwrap();
    assert_envelope(&stdout, &report, exit);
    assert_eq!(report["command"], "preview");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "template.locale-unavailable"
    );
}

#[test]
fn every_report_names_its_command_and_status() {
    let (_guard, root) = workspace();
    let (project, _) = starter(&root);
    let missing = root.join("missing.yaml");

    let (_, init) = invoke(path_arguments(&["init"], &root.join("second")));
    assert_eq!(
        (&init["command"], &init["status"]),
        (&json!("init"), &json!("complete"))
    );
    let (_, check) = invoke(path_arguments(&["check", "--project"], &project));
    assert_eq!(
        (&check["command"], &check["status"]),
        (&json!("check"), &json!("complete"))
    );
    let mut package = path_arguments(&["package"], &project);
    package.push(OsString::from("--output"));
    package.push(root.join("installed").into_os_string());
    package.push(OsString::from("--dry-run"));
    let (_, package) = invoke(package);
    assert_eq!(
        (&package["command"], &package["status"]),
        (&json!("package"), &json!("complete"))
    );

    for (command, arguments) in database_commands(&missing) {
        let (exit, report) = invoke(arguments);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT), "{report}");
        assert_eq!(report["command"], command, "{report}");
        assert_eq!(report["status"], "operational-failure", "{report}");
    }

    let (_, token) = invoke({
        let mut all = arguments(&["dev", "token", "client"]);
        all.push(root.join("absent").into_os_string());
        all
    });
    assert_eq!(token["command"], "dev token");
    let (_, dev) = invoke(path_arguments(&["dev"], &root.join("absent")));
    assert_eq!(dev["command"], "dev");
}

#[test]
fn a_failure_without_its_own_report_is_named_by_its_exit_class() {
    let (_guard, root) = workspace();
    let (project, _) = starter(&root);

    let (exit, report) = invoke(arguments(&["check"]));
    assert_eq!(exit, ExitCode::from(USAGE_EXIT));
    assert_eq!(report["command"], "usage");
    assert_eq!(report["status"], "usage-error");
    assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
    assert_eq!(report["diagnostics"][0]["artifact"], "command_arguments");
    assert_eq!(report["diagnostics"][0]["path"], "arguments");

    let (exit, report) = invoke(path_arguments(
        &["check", "--runtime-config"],
        &root.join("missing.yaml"),
    ));
    assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
    assert_eq!(report["command"], "check");
    assert_eq!(report["status"], "operational-failure");

    let (exit, report) = invoke(path_arguments(&["init"], &project));
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
    assert_eq!(report["command"], "init");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(report["diagnostics"][0]["code"], "init.exists");
}

#[test]
fn a_usage_error_never_repeats_a_rejected_argument_value() {
    let sentinel = "sentinel-7f3a9c";
    let unknown = format!("--reason={sentinel}");
    let refusals: [(&[&str], &str); 5] = [
        (
            &[
                "messages",
                "show",
                sentinel,
                "--runtime-config",
                "runtime.yaml",
            ],
            "<MESSAGE_ID>",
        ),
        (
            &[
                "retention",
                "erase-expired",
                "--runtime-config",
                "runtime.yaml",
                "--before",
                sentinel,
            ],
            "--before",
        ),
        (
            &[
                "messages",
                "list",
                "--runtime-config",
                "runtime.yaml",
                "--limit",
                sentinel,
            ],
            "--limit",
        ),
        (
            &[
                "messages",
                "list",
                "--runtime-config",
                "runtime.yaml",
                "--status",
                sentinel,
            ],
            "--status",
        ),
        (&["check", "--project", "project", &unknown], "--reason"),
    ];
    for (arguments, argument) in refusals {
        for format in ["human", "json"] {
            let mut all = vec![OsString::from("messagingctl"), OsString::from("--format")];
            all.push(OsString::from(format));
            all.extend(arguments.iter().map(OsString::from));
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit = main_entry_from(all, &mut stdout, &mut stderr);
            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            assert_eq!(exit, ExitCode::from(USAGE_EXIT), "{output}");
            assert!(!output.contains(sentinel), "{output}");
            assert!(output.contains(argument), "{output}");
            assert!(output.contains("--help"), "{output}");
            if format == "human" {
                assert!(stdout.is_empty(), "{output}");
            } else {
                assert!(stderr.is_empty(), "{output}");
            }
        }
    }
}

#[test]
fn a_validator_reason_survives_as_the_usage_message() {
    let refusals: [(&[&str], &str); 2] = [
        (
            &[
                "retention",
                "erase-expired",
                "--runtime-config",
                "runtime.yaml",
                "--before",
                "last-tuesday",
            ],
            "invalid value for --before: expected an RFC 3339 instant such as 2026-09-01T00:00:00Z",
        ),
        (
            &[
                "messages",
                "show",
                "not-a-message-id",
                "--runtime-config",
                "runtime.yaml",
            ],
            "invalid value for <MESSAGE_ID>: expected a UUID",
        ),
    ];
    for (arguments, message) in refusals {
        let (exit, report) = invoke(arguments.iter().map(OsString::from));
        assert_eq!(exit, ExitCode::from(USAGE_EXIT), "{report}");
        assert_eq!(report["diagnostics"][0]["message"], message);

        let mut all = vec![OsString::from("messagingctl")];
        all.extend(arguments.iter().map(OsString::from));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(all, &mut stdout, &mut stderr);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!("error: {message}\n  next: {USAGE_ACTION}\n")
        );
    }
}
