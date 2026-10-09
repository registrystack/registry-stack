//! Process-level conformance for the shared ctl convention: under
//! `--format json` every command writes one report on standard output, opening
//! with `ok`, `command`, and `status`; `ok` is true exactly when the process
//! exits 0; the exit code is one of the four classes; every key is camelCase;
//! and nothing is written to standard error.

#![cfg(unix)]

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use serde_json::Value;

const SUCCESS: i32 = 0;
const DOMAIN_REFUSAL: i32 = 1;
const USAGE: i32 = 2;
const OPERATIONAL_FAILURE: i32 = 3;

fn evidencectl() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
    command.env_remove("BREGCTL_BIN");
    command
}

/// A stub `evidence` binary that answers the version handshake with this
/// build's version and accepts every delegated check, so the envelope is
/// proved without depending on an installed runtime.
fn stub_evidence(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("evidence");
    let script = format!(
        r#"#!/bin/sh
if [ "${{1:-}}" = "--version" ]; then
  printf 'evidence %s\n' "{version}"
  exit 0
fi
for arg in "$@"; do
  if [ "$arg" = "bundle-check" ]; then
    printf '{{"packageDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","requirements":[{{"id":"urn:example:stub:record-active","configurationRevision":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}]}}\n'
    exit 0
  fi
done
if [ "${{1:-}}" = "render-discovery-description" ]; then
  printf '{{}}\n'
fi
exit 0
"#,
        version = registry_platform_buildinfo::DISPLAY_VERSION
    );
    fs::write(&path, script).expect("write stub evidence");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
    path
}

/// Assert the envelope contract on one run and return its report.
fn conforming(output: &Output, command: &str, exit: i32, status: &str) -> Value {
    let stdout = String::from_utf8(output.stdout.clone()).expect("utf8 stdout");
    assert_eq!(
        output.status.code(),
        Some(exit),
        "{command}: stdout {stdout} stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{command} wrote to stderr under --format json: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout.trim_end().lines().count(),
        1,
        "{command} must write exactly one report line: {stdout}"
    );
    let expected_head = format!(
        r#"{{"ok":{},"command":{},"status":{},"#,
        exit == SUCCESS,
        Value::String(command.to_owned()),
        Value::String(status.to_owned())
    );
    assert!(
        stdout.starts_with(&expected_head),
        "{command} report must open with {expected_head}: {stdout}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("one JSON report");
    assert_camel_case(&report, "$");
    if exit != SUCCESS {
        let diagnostics = report["diagnostics"]
            .as_array()
            .filter(|diagnostics| !diagnostics.is_empty())
            .unwrap_or_else(|| panic!("{command}: a refusal carries diagnostics: {stdout}"));
        for diagnostic in diagnostics {
            for key in ["severity", "code", "artifact", "path", "message"] {
                assert!(diagnostic.get(key).is_some(), "{command}: no {key}");
            }
            assert!(
                diagnostic["suggestedAction"]
                    .as_str()
                    .is_some_and(|action| !action.is_empty()),
                "{command}: every refusal names the next step"
            );
        }
    }
    report
}

fn assert_camel_case(value: &Value, path: &str) {
    match value {
        Value::Object(members) => {
            for (key, member) in members {
                assert!(
                    key.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                        && key.chars().all(|c| c.is_ascii_alphanumeric()),
                    "{path}.{key} is not a camelCase key"
                );
                assert_camel_case(member, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_camel_case(item, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

fn scaffold(root: &Path) -> std::path::PathBuf {
    let project = root.join("project");
    let output = evidencectl()
        .args(["--format", "json", "init"])
        .arg(&project)
        .args(["--transport", "sqlite-extract", "--profile", "local"])
        .output()
        .expect("run init");
    conforming(&output, "init", SUCCESS, "created");
    project
}

#[test]
fn usage_errors_use_the_envelope_and_exit_two() {
    let output = evidencectl()
        .args(["--format", "json", "check"])
        .output()
        .expect("run check");
    let report = conforming(&output, "usage", USAGE, "usage-error");
    assert_eq!(report["diagnostics"][0]["code"], "evidencectl.usage");

    let output = evidencectl()
        .args(["--format", "json", "target", "new", "target", "--local"])
        .output()
        .expect("run target new");
    let report = conforming(&output, "target new", USAGE, "usage-error");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidencectl.format.unsupported"
    );
}

#[test]
fn a_malformed_name_prefix_is_a_usage_error() {
    let workspace = tempfile::tempdir().expect("workspace");
    let output = evidencectl()
        .args(["--format", "json", "dev", "start"])
        .arg(workspace.path())
        .args(["--name-prefix", "CI_Job"])
        .output()
        .expect("run dev start");
    let report = conforming(&output, "usage", USAGE, "usage-error");
    assert_eq!(report["diagnostics"][0]["code"], "evidencectl.usage");

    let output = evidencectl()
        .args(["dev", "start"])
        .arg(workspace.path())
        .args(["--name-prefix", "CI_Job"])
        .output()
        .expect("run dev start");
    assert_eq!(output.status.code(), Some(USAGE));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--help"),
        "the refusal names the next step: {stderr}"
    );

    // The usage refusal is value-free, so the help it points to carries the rule.
    let output = evidencectl()
        .args(["dev", "start", "--help"])
        .output()
        .expect("run dev start --help");
    let help = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        help.contains("lowercase letters, digits, and") && help.contains("at most 32"),
        "{help}"
    );
}

#[test]
fn init_check_and_explain_share_the_envelope() {
    let workspace = tempfile::tempdir().expect("workspace");
    let project = scaffold(workspace.path());
    let evidence = stub_evidence(workspace.path());

    let output = evidencectl()
        .env("EVIDENCE_BIN", &evidence)
        .args(["--format", "json", "check"])
        .arg(&project)
        .output()
        .expect("run check");
    let passing = conforming(&output, "check", SUCCESS, "complete");

    let output = evidencectl()
        .env("EVIDENCE_BIN", &evidence)
        .args(["--format", "json", "explain"])
        .arg(&project)
        .output()
        .expect("run explain");
    let explained = conforming(&output, "explain", SUCCESS, "complete");

    let question = fs::read_dir(project.join("questions"))
        .expect("questions")
        .map(|entry| entry.expect("entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .expect("the scaffold ships a question");
    let text = fs::read_to_string(&question).expect("question text");
    fs::write(
        &question,
        text.replacen("purpose:", "purpose: [unclosed", 1),
    )
    .expect("corrupt");

    for (command, passing) in [("check", &passing), ("explain", &explained)] {
        let output = evidencectl()
            .env("EVIDENCE_BIN", &evidence)
            .args(["--format", "json", command])
            .arg(&project)
            .output()
            .expect("run refused command");
        let refused = conforming(&output, command, DOMAIN_REFUSAL, "refused");
        let keys = |report: &Value| {
            report
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(keys(&refused), keys(passing), "{command} key sets diverge");
    }
}

#[test]
fn key_and_access_commands_share_the_envelope() {
    let workspace = tempfile::tempdir().expect("workspace");
    let keys = workspace.path().join("keys");
    let output = evidencectl()
        .args(["--format", "json", "keygen", "signing", "--output-dir"])
        .arg(&keys)
        .output()
        .expect("run keygen");
    let report = conforming(&output, "keygen signing", SUCCESS, "complete");
    let public = report["files"]
        .as_array()
        .expect("keygen names its files")
        .iter()
        .filter_map(Value::as_str)
        .find(|file| file.ends_with("public.jwk.json"))
        .expect("keygen names its public JWK")
        .to_owned();

    let output = evidencectl()
        .args(["--format", "json", "jwks", "--output"])
        .arg(workspace.path().join("jwks.json"))
        .arg(&public)
        .output()
        .expect("run jwks");
    conforming(&output, "jwks", SUCCESS, "complete");

    let project = scaffold(workspace.path());
    let output = evidencectl()
        .current_dir(&project)
        .args(["--format", "json", "access", "policy", "list"])
        .output()
        .expect("run access policy list");
    conforming(&output, "access policy list", SUCCESS, "complete");
}

#[test]
fn refusals_name_the_command_that_refused() {
    let workspace = tempfile::tempdir().expect("workspace");
    let missing = workspace.path().join("missing");

    let output = evidencectl()
        .args(["--format", "json", "artifact", "inspect"])
        .arg(&missing)
        .output()
        .expect("run artifact inspect");
    conforming(
        &output,
        "artifact inspect",
        DOMAIN_REFUSAL,
        "domain-refusal",
    );

    let output = evidencectl()
        .args(["--format", "json", "target", "explain"])
        .arg(&missing)
        .arg(&missing)
        .output()
        .expect("run target explain");
    // A target file that cannot be read is an unavailable file, not a
    // refused one.
    conforming(
        &output,
        "target explain",
        OPERATIONAL_FAILURE,
        "operational-failure",
    );

    // A project with no running local session lacks the service the command
    // depends on; the refusal names `dev start`.
    let output = evidencectl()
        .args(["--format", "json", "dev", "stop"])
        .arg(workspace.path())
        .output()
        .expect("run dev stop");
    let report = conforming(
        &output,
        "dev stop",
        OPERATIONAL_FAILURE,
        "operational-failure",
    );
    assert!(
        report["diagnostics"][0]["suggestedAction"]
            .as_str()
            .is_some_and(|action| action.contains("evidencectl dev start")),
        "{report}"
    );

    let output = evidencectl()
        .args(["--format", "json", "audit", "show", "--last-operation"])
        .current_dir(workspace.path())
        .output()
        .expect("run audit show");
    conforming(&output, "audit show", DOMAIN_REFUSAL, "domain-refusal");

    let output = evidencectl()
        .args(["--format", "json", "jwks", "--output"])
        .arg(workspace.path().join("jwks.json"))
        .arg(&missing)
        .output()
        .expect("run jwks");
    conforming(&output, "jwks", OPERATIONAL_FAILURE, "operational-failure");
}

#[test]
fn the_retired_project_flag_is_refused() {
    let workspace = tempfile::tempdir().expect("workspace");
    let project = scaffold(workspace.path());
    let output = evidencectl()
        .args(["--format", "json", "tooling", "editor", "--project"])
        .arg(&project)
        .output()
        .expect("run tooling editor");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn an_undeliverable_report_exits_operational() {
    let workspace = tempfile::tempdir().expect("workspace");
    let keys = workspace.path().join("keys");
    // A pipe whose reader is already gone refuses every write, as a
    // consumer that went away would.
    let (reader, stdout) = std::io::pipe().expect("stdout pipe");
    drop(reader);
    let output = evidencectl()
        .args(["--format", "json", "keygen", "signing", "--output-dir"])
        .arg(&keys)
        .stdout(stdout)
        .output()
        .expect("run keygen");
    assert_eq!(
        output.status.code(),
        Some(OPERATIONAL_FAILURE),
        "stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not write the JSON report"),
        "the only channel left names the failure: {stderr}"
    );
}

#[test]
fn undeliverable_json_help_exits_operational() {
    let (reader, stdout) = std::io::pipe().expect("stdout pipe");
    drop(reader);
    let output = evidencectl()
        .args(["--format", "json", "--help"])
        .stdout(stdout)
        .output()
        .expect("run help");
    assert_eq!(
        output.status.code(),
        Some(OPERATIONAL_FAILURE),
        "stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not write the JSON report"));
}
