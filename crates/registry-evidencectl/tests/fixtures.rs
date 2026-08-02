#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

/// Build a minimal deployment project: `runtime.yaml` at the root and a
/// `bundle/evidence.yaml` whose requirements reference the given
/// bundle-relative fixture paths. The driver only ever parses this file to
/// enumerate fixtures, so its other fields are placeholders.
fn write_project(root: &Path, fixture_paths: &[&str]) -> PathBuf {
    let project = root.join("project");
    fs::create_dir_all(project.join("bundle")).expect("create bundle dir");
    fs::write(project.join("runtime.yaml"), b"placeholder: true\n").expect("write runtime.yaml");

    let mut requirements = String::new();
    for (index, fixture_path) in fixture_paths.iter().enumerate() {
        requirements.push_str(&format!(
            "  - id: urn:example:fixture:requirement:{index}\n    fixtures: {fixture_path}\n"
        ));
    }
    let evidence_yaml = format!("version: 1\nrequirements:\n{requirements}");
    fs::write(project.join("bundle").join("evidence.yaml"), evidence_yaml)
        .expect("write bundle evidence.yaml");
    project
}

/// Write a stub `evidence` binary that:
/// - appends its argv (one argument per line, `===` between invocations) to
///   the file named by `$ARGV_LOG`;
/// - exits 1 with a fixed diagnostic on stderr when its step name equals
///   `$FAIL_STEP` (`check`, or `evaluate:<fixture path>`), and exits 0
///   otherwise.
fn write_stub_evidence(dir: &Path) -> PathBuf {
    let path = dir.join("evidence");
    let script = r#"#!/bin/sh
set -eu

for arg in "$@"; do
  printf '%s\n' "$arg" >> "$ARGV_LOG"
done
printf '===\n' >> "$ARGV_LOG"

fixture=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--fixture" ]; then
    fixture="$arg"
  fi
  prev="$arg"
done

step="check"
for arg in "$@"; do
  case "$arg" in
    evaluate) step="evaluate" ;;
  esac
done
if [ -n "$fixture" ]; then
  step="evaluate:$fixture"
fi

if [ "$step" = "${FAIL_STEP:-}" ]; then
  printf 'stub failure for %s\n' "$step" >&2
  exit 1
fi

printf 'stub ok for %s\n' "$step"
exit 0
"#;
    fs::write(&path, script).expect("write stub evidence script");
    let mut permissions = fs::metadata(&path).expect("stat stub").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod stub");
    path
}

/// Parse the argv log into one `Vec<String>` per invocation, in call order.
fn read_argv_log(path: &Path) -> Vec<Vec<String>> {
    let contents = fs::read_to_string(path).unwrap_or_default();
    contents
        .split("===\n")
        .filter(|block| !block.is_empty())
        .map(|block| block.lines().map(str::to_owned).collect())
        .collect()
}

#[test]
fn happy_path_runs_check_then_each_fixture_and_reports_pass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = write_project(dir.path(), &["fixtures/a.yaml", "fixtures/b.yaml"]);
    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&stub)
        .env("ARGV_LOG", &argv_log)
        .env_remove("FAIL_STEP")
        .output()
        .expect("run evidencectl");

    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("PASS: check"), "{stdout}");
    assert!(stdout.contains("PASS: fixtures/a.yaml"), "{stdout}");
    assert!(stdout.contains("PASS: fixtures/b.yaml"), "{stdout}");
    assert!(stdout.contains("3 passed, 0 failed"), "{stdout}");

    let runtime_path = project.join("runtime.yaml");
    let runtime_path = runtime_path.to_str().expect("runtime path is utf8");
    let invocations = read_argv_log(&argv_log);
    assert_eq!(
        invocations,
        vec![
            vec!["--runtime", runtime_path, "check"],
            vec![
                "--runtime",
                runtime_path,
                "evaluate",
                "--fixture",
                "fixtures/a.yaml"
            ],
            vec![
                "--runtime",
                runtime_path,
                "evaluate",
                "--fixture",
                "fixtures/b.yaml"
            ],
        ],
        "unexpected evidence invocations"
    );
}

#[test]
fn check_failure_short_circuits_before_any_fixture_evaluation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = write_project(dir.path(), &["fixtures/a.yaml", "fixtures/b.yaml"]);
    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&stub)
        .env("ARGV_LOG", &argv_log)
        .env("FAIL_STEP", "check")
        .output()
        .expect("run evidencectl");

    assert!(
        !output.status.success(),
        "expected nonzero exit on check failure"
    );
    let stdout = stdout_of(&output);
    assert!(stdout.contains("FAIL: check"), "{stdout}");
    assert!(stdout.contains("stub failure for check"), "{stdout}");
    assert!(stdout.contains("0 passed, 1 failed"), "{stdout}");
    assert!(
        !stdout.contains("fixtures/a.yaml") && !stdout.contains("fixtures/b.yaml"),
        "no fixture should have been reported: {stdout}"
    );

    let invocations = read_argv_log(&argv_log);
    assert_eq!(
        invocations.len(),
        1,
        "evaluate must never be invoked once check fails: {invocations:?}"
    );
}

#[test]
fn one_failing_fixture_is_reported_with_its_stderr_and_the_rest_still_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = write_project(dir.path(), &["fixtures/a.yaml", "fixtures/b.yaml"]);
    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&stub)
        .env("ARGV_LOG", &argv_log)
        .env("FAIL_STEP", "evaluate:fixtures/b.yaml")
        .output()
        .expect("run evidencectl");

    assert!(
        !output.status.success(),
        "expected nonzero exit on fixture failure"
    );
    let stdout = stdout_of(&output);
    assert!(stdout.contains("PASS: check"), "{stdout}");
    assert!(stdout.contains("PASS: fixtures/a.yaml"), "{stdout}");
    assert!(stdout.contains("FAIL: fixtures/b.yaml"), "{stdout}");
    assert!(
        stdout.contains("stub failure for evaluate:fixtures/b.yaml"),
        "failing step's stderr must be included: {stdout}"
    );
    assert!(stdout.contains("2 passed, 1 failed"), "{stdout}");

    let invocations = read_argv_log(&argv_log);
    assert_eq!(
        invocations.len(),
        3,
        "every fixture must still run despite one failure: {invocations:?}"
    );
}

#[test]
fn json_output_is_one_parseable_document_on_stdout_with_expected_pass_fail_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = write_project(dir.path(), &["fixtures/a.yaml", "fixtures/b.yaml"]);
    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&stub)
        .arg("--json")
        .env("ARGV_LOG", &argv_log)
        .env("FAIL_STEP", "evaluate:fixtures/b.yaml")
        .output()
        .expect("run evidencectl");

    assert!(!output.status.success());
    let stdout = stdout_of(&output);
    let stdout_lines: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(
        stdout_lines.len(),
        1,
        "stdout must carry exactly one JSON document: {stdout}"
    );

    let report: serde_json::Value =
        serde_json::from_str(stdout_lines[0]).expect("parse JSON report");
    assert_eq!(report["passed"], serde_json::Value::Bool(false));
    assert_eq!(report["check"]["passed"], serde_json::Value::Bool(true));
    let fixtures = report["fixtures"].as_array().expect("fixtures array");
    assert_eq!(fixtures.len(), 2);
    assert_eq!(fixtures[0]["path"], "fixtures/a.yaml");
    assert_eq!(fixtures[0]["passed"], serde_json::Value::Bool(true));
    assert_eq!(fixtures[1]["path"], "fixtures/b.yaml");
    assert_eq!(fixtures[1]["passed"], serde_json::Value::Bool(false));
    assert!(fixtures[1]["stderr"]
        .as_str()
        .expect("failing fixture carries stderr")
        .contains("stub failure for evaluate:fixtures/b.yaml"));

    // Human diagnostics belong on stderr in JSON mode, not on stdout.
    let stderr = stderr_of(&output);
    assert!(stderr.contains("FAIL: fixtures/b.yaml"), "{stderr}");
}

#[test]
fn missing_runtime_yaml_errors_clearly_without_invoking_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = dir.path().join("project");
    fs::create_dir_all(&project).expect("create project dir");
    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&stub)
        .env("ARGV_LOG", &argv_log)
        .output()
        .expect("run evidencectl");

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("runtime.yaml"), "{stderr}");
    assert!(!argv_log.exists(), "evidence must never be invoked");
}

#[test]
fn unresolvable_evidence_binary_errors_clearly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = write_project(dir.path(), &["fixtures/a.yaml"]);
    let missing_bin = dir.path().join("nowhere").join("evidence");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&missing_bin)
        .output()
        .expect("run evidencectl");

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("evidence binary not found"), "{stderr}");
    assert!(
        stderr.contains(missing_bin.to_str().expect("utf8 path")),
        "{stderr}"
    );
}

#[test]
fn fixtures_are_discovered_at_a_relative_bundle_directory_named_in_runtime_yaml() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = dir.path().join("project");
    fs::create_dir_all(project.join("custom-bundle")).expect("create custom bundle dir");
    fs::write(
        project.join("runtime.yaml"),
        b"placeholder: true\nbundleDirectory: custom-bundle\n",
    )
    .expect("write runtime.yaml");
    fs::write(
        project.join("custom-bundle").join("evidence.yaml"),
        "version: 1\nrequirements:\n  - id: urn:example:fixture:requirement:0\n    fixtures: fixtures/a.yaml\n",
    )
    .expect("write bundle evidence.yaml");

    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&stub)
        .env("ARGV_LOG", &argv_log)
        .env_remove("FAIL_STEP")
        .output()
        .expect("run evidencectl");

    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("PASS: fixtures/a.yaml"), "{stdout}");
    assert!(stdout.contains("2 passed, 0 failed"), "{stdout}");
}

#[test]
fn fixtures_are_discovered_at_an_absolute_bundle_directory_named_in_runtime_yaml() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = dir.path().join("project");
    fs::create_dir_all(&project).expect("create project dir");
    let bundle_directory = dir.path().join("elsewhere").join("bundle");
    fs::create_dir_all(&bundle_directory).expect("create bundle dir");

    let runtime_yaml = format!(
        "placeholder: true\nbundleDirectory: {}\n",
        bundle_directory.to_str().expect("bundle directory is utf8")
    );
    fs::write(project.join("runtime.yaml"), runtime_yaml).expect("write runtime.yaml");
    fs::write(
        bundle_directory.join("evidence.yaml"),
        "version: 1\nrequirements:\n  - id: urn:example:fixture:requirement:0\n    fixtures: fixtures/a.yaml\n",
    )
    .expect("write bundle evidence.yaml");

    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&stub)
        .env("ARGV_LOG", &argv_log)
        .env_remove("FAIL_STEP")
        .output()
        .expect("run evidencectl");

    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("PASS: fixtures/a.yaml"), "{stdout}");
    assert!(stdout.contains("2 passed, 0 failed"), "{stdout}");
}

#[test]
fn a_non_executable_evidence_on_path_is_skipped_with_a_clear_resolution_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = write_project(dir.path(), &["fixtures/a.yaml"]);

    let path_dir = dir.path().join("path-entry");
    fs::create_dir(&path_dir).expect("create path entry dir");
    let candidate = path_dir.join("evidence");
    fs::write(&candidate, b"#!/bin/sh\nexit 0\n").expect("write candidate");
    let mut permissions = fs::metadata(&candidate)
        .expect("stat candidate")
        .permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&candidate, permissions).expect("chmod candidate non-executable");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .env("PATH", &path_dir)
        .env_remove("EVIDENCE_BIN")
        .output()
        .expect("run evidencectl");

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("evidence binary not found"),
        "a non-executable candidate on PATH must be skipped: {stderr}"
    );
}

#[test]
fn evidence_bin_env_var_is_used_when_the_flag_is_omitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = write_project(dir.path(), &["fixtures/a.yaml"]);
    let stub = write_stub_evidence(dir.path());
    let argv_log = dir.path().join("argv.log");

    let output = evidencectl()
        .args(["fixtures", "run", "--project"])
        .arg(&project)
        .env("EVIDENCE_BIN", &stub)
        .env("ARGV_LOG", &argv_log)
        .output()
        .expect("run evidencectl");

    assert!(output.status.success(), "{}", stderr_of(&output));
    let invocations = read_argv_log(&argv_log);
    assert_eq!(invocations.len(), 2, "check plus one fixture");
}
