// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `adapterctl check` and `adapterctl schemas`, run
//! against the minimal fixture project under `tests/fixtures/minimal`.

use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

/// The minimal fixture project's `project.yaml`.
fn minimal_project() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/minimal/project.yaml")
        .to_str()
        .unwrap()
        .to_owned()
}

/// Run one invocation in JSON mode and return its exit code, its report
/// (null when stdout carried no report), and its stderr.
fn run_json(arguments: &[&str]) -> (ExitCode, Value, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut all = vec![
        OsString::from("adapterctl"),
        OsString::from("--format=json"),
    ];
    all.extend(arguments.iter().map(OsString::from));
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    let report = serde_json::from_slice(&stdout).unwrap_or(Value::Null);
    assert_envelope(&stdout, &report, exit);
    (exit, report, stderr)
}

/// Every JSON report opens with `ok`, `command`, and `status` in that
/// order, then names its format; `ok` is true exactly when the process
/// exits zero, and a report that is not ok carries at least one
/// diagnostic naming the next step.
fn assert_envelope(stdout: &[u8], report: &Value, exit: ExitCode) {
    let text = String::from_utf8_lossy(stdout);
    let head = text
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once('"').map(|(key, _)| key))
        .take(5)
        .collect::<Vec<_>>();
    assert_eq!(
        head,
        ["ok", "command", "status", "apiVersion", "kind"],
        "{text}"
    );
    assert_eq!(
        report["apiVersion"],
        "id.registrystack.org/formats/adapter/ctl-report/v1alpha1"
    );
    assert_eq!(report["kind"], "AdapterCtlReport");
    assert!(report["command"].as_str().is_some_and(|c| !c.is_empty()));
    assert!(report["status"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(report["ok"], json!(exit == ExitCode::SUCCESS), "{text}");
    if exit != ExitCode::SUCCESS {
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        assert!(!diagnostics.is_empty(), "{text}");
        for diagnostic in diagnostics {
            assert!(
                diagnostic["suggestedAction"]
                    .as_str()
                    .is_some_and(|action| !action.is_empty()),
                "{text}"
            );
        }
    }
}

/// A missing subcommand is a usage error.
#[test]
fn a_missing_subcommand_is_a_usage_error() {
    let (exit, report, _) = run_json(&[]);
    assert_eq!(exit, ExitCode::from(2));
    assert_eq!(report["command"], "usage");
    assert_eq!(report["status"], "usage-error");
}

/// The minimal valid fixture project checks green: every file is read,
/// the diagnostics are empty, and stderr stays clean.
#[test]
fn the_minimal_fixture_project_checks_green() {
    let (exit, report, stderr) = run_json(&["check", &minimal_project()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["command"], "check");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["filesChecked"], 5);
    assert_eq!(report["diagnostics"], json!([]));
}

/// Copy the minimal fixture project into a fresh directory and hand the
/// copy's `project.yaml` back with the directory guard that keeps it
/// alive. `mutate` edits the copy in place.
fn mutated_project(mutate: impl FnOnce(&Path)) -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("minimal");
    copy_fs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal"),
        &copy,
    );
    mutate(&copy);
    let project = copy.join("project.yaml").to_str().unwrap().to_owned();
    (root, project)
}

/// Recursively copy a fixture tree (a handful of small files).
fn copy_fs(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_fs(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Replace one exact occurrence of `from` with `to` in the file.
fn edit(file: &Path, from: &str, to: &str) {
    let contents = std::fs::read_to_string(file).unwrap();
    let edited = contents.replacen(from, to, 1);
    assert_ne!(contents, edited, "the edit must change {file:?}");
    std::fs::write(file, edited).unwrap();
}

/// Assert a refusal: exit 1, domain-refusal, and `code` among the
/// diagnostics.
fn assert_refused(exit: ExitCode, report: &Value, code: &str) {
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["status"], "domain-refusal", "{report}");
    let codes = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(codes.contains(&code), "expected {code} among {codes:?}");
}

/// A project whose kind no format declares refuses with the reader's
/// wrong-kind code. The undecoded project stops the run after the reads:
/// the script digest verification never opens, so one file fewer is
/// counted than on a green pass.
#[test]
fn a_wrong_kind_refuses_with_the_reader_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "kind: AdapterProject",
            "kind: AdapterProfile",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "config.wrong-kind");
    assert_eq!(report["filesChecked"], 4, "{report}");
}

/// A project carrying an apiVersion no format declares refuses.
#[test]
fn an_unsupported_api_version_refuses_with_the_reader_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1",
            "apiVersion: id.registrystack.org/formats/adapter/project/v9alpha9",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "config.unsupported-api-version");
}

/// A project missing an envelope member refuses.
#[test]
fn a_missing_envelope_member_refuses_with_the_reader_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1\n",
            "",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "config.missing-envelope");
}

/// A pack whose pinned script file is missing refuses with the pack's
/// digest-pin code.
#[test]
fn a_missing_pinned_script_refuses_with_the_digest_pin_code() {
    let (_root, project) = mutated_project(|root| {
        std::fs::remove_file(root.join("scripts/map.rhai")).unwrap();
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.digest-pin-required");
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "adapter.pack.digest-pin-required")
        .unwrap();
    assert_eq!(
        diagnostic["message"], "the pinned file is missing",
        "{diagnostic}"
    );
}

/// A pack whose pinned script no longer hashes to its digest refuses.
#[test]
fn an_altered_pinned_script_refuses_with_the_digest_pin_code() {
    let (_root, project) = mutated_project(|root| {
        let script = root.join("scripts/map.rhai");
        let contents = std::fs::read_to_string(&script).unwrap();
        std::fs::write(&script, contents.replace("body", "renamed")).unwrap();
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.digest-pin-required");
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "adapter.pack.digest-pin-required")
        .unwrap();
    assert_eq!(
        diagnostic["message"], "the file does not hash to its digest pin",
        "{diagnostic}"
    );
}

/// A pinned script that no longer parses refuses with the compile code
/// beside the digest-pin code: one pass names everything to fix, and the
/// refusal never quotes the script's own text.
#[test]
fn an_uncompilable_script_refuses_with_the_compile_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("scripts/map.rhai"),
            "fn map(body) {\n    body\n}",
            "fn map(body) {\n    body",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.script-uncompilable");
    assert_refused(exit, &report, "adapter.pack.digest-pin-required");
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(
        !rendered.contains("expecting"),
        "the refusal must stay value-free: {rendered}"
    );
}

/// A pinned script that parses but declares no function under the
/// entrypoint name the pack routes name refuses with the compile code.
#[test]
fn a_script_without_the_declared_entrypoint_refuses_with_the_compile_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("scripts/map.rhai"),
            "fn map(body) {\n    body\n}",
            "fn other(input) {\n    input\n}",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.script-uncompilable");
}

/// Assert `code` carries no diagnostic in the report.
fn assert_code_absent(report: &Value, code: &str) {
    let codes = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(!codes.contains(&code), "expected no {code} among {codes:?}");
}

/// The JSON pointer of the one diagnostic carrying `code`.
fn diagnostic_path(report: &Value, code: &str) -> String {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == code)
        .map(|diagnostic| diagnostic["path"].as_str().unwrap().to_owned())
        .unwrap_or_else(|| panic!("expected {code} among the diagnostics"))
}

/// A profile edited after the project pinned it refuses with the digest
/// code at the profile pointer alone: the version pin still holds.
#[test]
fn a_tampered_profile_refuses_with_the_pin_digest_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("profile.yaml"),
            "id: case-api",
            "id: case-api\n# edited after pinning",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.project.pin-digest-mismatch");
    assert_code_absent(&report, "adapter.project.pin-version-mismatch");
    assert_eq!(
        diagnostic_path(&report, "adapter.project.pin-digest-mismatch"),
        "/profile/digest"
    );
}

/// A project pin naming a version the profile bytes do not carry refuses
/// with the version code at the profile pointer alone: the digest pin
/// still holds.
#[test]
fn a_wrong_pinned_profile_version_refuses_with_the_pin_version_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "profile:\n  id: case-api\n  version: 1.0.0",
            "profile:\n  id: case-api\n  version: 9.9.9",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.project.pin-version-mismatch");
    assert_code_absent(&report, "adapter.project.pin-digest-mismatch");
    assert_eq!(
        diagnostic_path(&report, "adapter.project.pin-version-mismatch"),
        "/profile/version"
    );
}

/// An expected facade body carrying a member the bound record type does
/// not declare refuses at that member's pointer.
#[test]
fn an_expected_body_with_an_unknown_member_refuses_with_the_response_schema_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("fixtures/records.yaml"),
            "          national_id: \"123\"",
            "          national_id: \"123\"\n          ghost: true",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.fixture.response-schema");
    assert_eq!(
        diagnostic_path(&report, "adapter.fixture.response-schema"),
        "/entries/0/expectedFacadeResponse/body/record/ghost"
    );
}

/// An expected facade body typing a record member wrongly refuses at that
/// member's pointer.
#[test]
fn an_expected_body_with_a_wrong_typed_member_refuses_with_the_response_schema_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("fixtures/records.yaml"),
            "          national_id: \"123\"",
            "          national_id: 7",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.fixture.response-schema");
    assert_eq!(
        diagnostic_path(&report, "adapter.fixture.response-schema"),
        "/entries/0/expectedFacadeResponse/body/record/national_id"
    );
}

/// An expected facade body missing a required record member refuses at
/// that member's pointer.
#[test]
fn an_expected_body_missing_a_required_member_refuses_with_the_response_schema_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("fixtures/records.yaml"),
            "        record:\n          national_id: \"123\"",
            "        record: {}",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.fixture.response-schema");
    assert_eq!(
        diagnostic_path(&report, "adapter.fixture.response-schema"),
        "/entries/0/expectedFacadeResponse/body/record/national_id"
    );
}

/// An expected facade response without a body refuses where the
/// operation's result schema requires one.
#[test]
fn an_expected_body_absent_refuses_with_the_response_schema_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("fixtures/records.yaml"),
            "      body:\n        record:\n          national_id: \"123\"",
            "",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.fixture.response-schema");
    assert_eq!(
        diagnostic_path(&report, "adapter.fixture.response-schema"),
        "/entries/0/expectedFacadeResponse"
    );
}

/// An entry naming an operation the bound profile does not declare
/// refuses with the core pairing code: `adapterctl check` runs the core
/// fixture checks, it never reimplements them.
#[test]
fn an_entry_with_an_unknown_operation_refuses_with_the_operation_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("fixtures/records.yaml"),
            "- operation: cases.get",
            "- operation: cases.ghost",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.fixture.unknown-operation");
}

/// An entry naming an operation the profile declares but the project
/// binds to no route refuses with the core pairing code.
#[test]
fn an_entry_with_an_unbound_operation_refuses_with_the_operation_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "bindings:\n  - id: find-cases\n    operation: cases.get\n    recordType: case\n    route: fetchCases\n    maximumUpstreamCalls: 5",
            "bindings: []",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.fixture.unknown-operation");
}

/// An instantiation naming no declared template refuses with the core
/// code, and the refusal never repeats the rejected identifier.
#[test]
fn an_unknown_template_refuses_with_the_core_code_and_stays_value_free() {
    let ghost = "ghost-template-7f3a9c";
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "routeTemplateRef: fetchPage",
            &format!("routeTemplateRef: {ghost}"),
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.project.unknown-template");
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(
        !rendered.contains(ghost),
        "the refusal must stay value-free: {rendered}"
    );
}

/// A fixture without provenance refuses at the reader.
#[test]
fn a_fixture_without_provenance_refuses_at_the_reader() {
    let (_root, project) = mutated_project(|root| {
        let fixture = root.join("fixtures/records.yaml");
        let contents = std::fs::read_to_string(&fixture).unwrap();
        let edited = contents
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                !(line.starts_with("provenance:")
                    || line.starts_with("reference:")
                    || line.starts_with("kind: documented"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&fixture, edited).unwrap();
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "config.missing-key");
}

/// A fixture naming no declared intercept endpoint refuses with the core
/// code.
#[test]
fn a_fixture_with_an_unknown_intercept_refuses_with_the_core_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("fixtures/records.yaml"),
            "endpoint: case-api",
            "endpoint: ghost-endpoint",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.fixture.unknown-intercept");
}

/// A project file that cannot be read is an operational failure, not a
/// domain refusal.
#[test]
fn an_unreadable_project_is_an_operational_failure() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/minimal/nowhere.yaml")
        .to_str()
        .unwrap()
        .to_owned();
    let (exit, report, _) = run_json(&["check", &missing]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
    assert_eq!(report["status"], "operational-failure", "{report}");
    assert_eq!(report["diagnostics"][0]["code"], "adapterctl.io-failure");
}

/// A fixtures path that cannot be read as a directory is an operational
/// failure, never a silently empty fixture set: a check that read no
/// fixtures must not pass as one that needed none.
#[test]
fn an_unreadable_fixtures_directory_is_an_operational_failure() {
    let (_root, project) = mutated_project(|root| {
        let fixtures = root.join("fixtures");
        std::fs::remove_dir_all(&fixtures).expect("drop the copied fixtures directory");
        std::fs::write(&fixtures, "not a directory\n").expect("write fixtures file");
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
    assert_eq!(report["status"], "operational-failure", "{report}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "adapterctl.io-failure");
    assert!(
        diagnostic["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("/fixtures")),
        "{report}"
    );
}

/// The human format prints the verdict line and the findings on stderr,
/// and stdout stays empty.
#[test]
fn the_human_refusal_names_the_code_on_stderr() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "routeTemplateRef: fetchPage",
            "routeTemplateRef: ghost",
        );
    });
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = registry_adapterctl::main_entry_from(
        ["adapterctl", "check", project.as_str()],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, ExitCode::from(1));
    assert!(stdout.is_empty(), "{}", String::from_utf8_lossy(&stdout));
    let text = String::from_utf8_lossy(&stderr);
    assert!(
        text.contains("adapterctl check refused the input."),
        "{text}"
    );
    assert!(
        text.contains("[adapter.project.unknown-template]"),
        "{text}"
    );
    assert!(text.contains("2 errors, 0 warnings in 5 files"), "{text}");
}

/// The human format of a passing check keeps stdout for the verdict and
/// stderr clean.
#[test]
fn the_human_success_prints_the_verdict_on_stdout() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = registry_adapterctl::main_entry_from(
        ["adapterctl", "check", minimal_project().as_str()],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, ExitCode::SUCCESS);
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.starts_with("Authoring check passed."), "{text}");
}

/// `schemas` writes the five generated files into any directory it is
/// given.
#[test]
fn schemas_writes_five_files_into_the_given_directory() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("schemas").to_str().unwrap().to_owned();
    let (exit, report, stderr) = run_json(&["schemas", "--output-dir", &output]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["command"], "schemas");
    assert_eq!(report["files"].as_array().unwrap().len(), 5);
    let written = std::fs::read_dir(&output).unwrap().count();
    assert_eq!(written, 5);
}

/// `schemas --check` refuses on a hand-edited committed file.
#[test]
fn schemas_check_refuses_a_hand_edited_file() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("schemas").to_str().unwrap().to_owned();
    let (_, _, _) = run_json(&["schemas", "--output-dir", &output]);
    let profile = Path::new(&output).join("profile.v1alpha1.schema.json");
    let contents = std::fs::read_to_string(&profile).unwrap();
    std::fs::write(
        &profile,
        contents.replacen("Registry Adapter facade profile", "Hand edited", 1),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["schemas", "--check", "--output-dir", &output]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["diagnostics"][0]["code"], "adapterctl.schemas.drift");
}
