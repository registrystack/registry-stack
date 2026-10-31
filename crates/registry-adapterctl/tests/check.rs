// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `adapterctl check`, `adapterctl project lock`,
//! and `adapterctl schemas`, run against the minimal fixture project under
//! `tests/fixtures/minimal`.

use serde_json::{json, Value};
use std::collections::BTreeSet;
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
    assert_eq!(report["filesChecked"], 6);
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
        // The alteration keeps the script on the ABI, so the refusal stays
        // the digest pin's: only the bytes moved.
        std::fs::write(&script, format!("{contents}\n// altered\n")).unwrap();
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
    // The common case is an edit on purpose, so the remedy leads with the
    // command that repins the inventory from the files on disk.
    assert_eq!(
        diagnostic["suggestedAction"],
        "Run adapterctl project lock to repin the inventory digest pins from the files beside the pack document, or restore the file as pinned.",
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
            "fn map(exchange) {\n    #{ national_id: exchange.body.id }\n}",
            "fn map(exchange) {\n    #{ national_id: exchange.body.id }",
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
            "fn map(exchange) {\n    #{ national_id: exchange.body.id }\n}",
            "fn other(input) {\n    #{ national_id: input.body.id }\n}",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.script-uncompilable");
}

/// A pinned script whose entrypoint takes a parameter by any other name
/// refuses with the signature code beside the digest-pin code: the script
/// ABI names the exchange slots' one parameter (`CONCEPT.md` section
/// 8.11.3), and the refusal never quotes the author's spelling.
#[test]
fn an_entrypoint_whose_parameter_is_not_exchange_refuses_with_the_signature_code() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("scripts/map.rhai"),
            "fn map(exchange) {\n    #{ national_id: exchange.body.id }\n}",
            "fn map(record) {\n    #{ national_id: record.body.id }\n}",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.entrypoint-parameter");
    assert_refused(exit, &report, "adapter.pack.digest-pin-required");
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(
        !rendered.contains("fn map"),
        "the refusal must stay value-free: {rendered}"
    );
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
        "/entries/0/expected/body/record/ghost"
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
        "/entries/0/expected/body/record/national_id"
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
        "/entries/0/expected/body/record/national_id"
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
        "/entries/0/expected"
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
            "      operation: cases-get",
            "      operation: cases.ghost",
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
            "bindings:\n  - id: find-cases\n    operation: cases-get\n    recordType: case\n    route: fetchCases\n    maximumUpstreamCalls: 5\n  - id: create-case",
            "bindings:\n  - id: create-case",
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
            "routeTemplate: fetch-page",
            &format!("routeTemplate: {ghost}"),
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
                    || line.starts_with("type: documented"))
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
            "routeTemplate: fetch-page",
            "routeTemplate: ghost",
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
    assert!(text.contains("2 errors, 0 warnings in 6 files"), "{text}");
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

/// A passing check says what its fixture pass covered: the contracts
/// only, never a send-by-send replay, so a green pass is not read as a
/// route test (CONCEPT 13.3).
#[test]
fn the_check_pass_names_the_fixture_scope() {
    let (_root, project) = mutated_project(|_| {});
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(
        report["fixtures"],
        json!("contracts only, replay not run"),
        "{report}"
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = registry_adapterctl::main_entry_from(
        ["adapterctl", "check", project.as_str()],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, ExitCode::SUCCESS);
    let text = String::from_utf8_lossy(&stdout);
    assert!(
        text.contains("fixtures: contracts only, replay not run"),
        "{text}"
    );
}

/// A fixture path given by `--fixtures` that does not exist refuses: a
/// silently empty fixture set would read as a clean pass.
#[test]
fn check_refuses_a_missing_explicit_fixture_path() {
    let (_root, project) = mutated_project(|_| {});
    let missing = _root.path().join("nope/fixtures.yaml");
    let (exit, report, _) = run_json(&["check", &project, "--fixtures", missing.to_str().unwrap()]);
    assert_refused(exit, &report, "adapterctl.fixture-path-missing");
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "adapterctl.fixture-path-missing")
        .unwrap();
    assert_eq!(diagnostic["path"], missing.to_str().unwrap(), "{report}");
    assert_eq!(
        diagnostic["message"], "the fixture file does not exist",
        "{diagnostic}"
    );
}

/// `schemas` writes the closed set of six generated files into any
/// directory it is given.
#[test]
fn schemas_writes_six_files_into_the_given_directory() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("schemas").to_str().unwrap().to_owned();
    let (exit, report, stderr) = run_json(&["schemas", "--output-dir", &output]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["command"], "schemas");
    let expected = BTreeSet::from([
        "effective-contract.v1alpha1.schema.json".to_owned(),
        "fixture.v1alpha1.schema.json".to_owned(),
        "pack.v1alpha1.schema.json".to_owned(),
        "profile.v1alpha1.schema.json".to_owned(),
        "project.v1alpha1.schema.json".to_owned(),
        "runtime.v1alpha1.schema.json".to_owned(),
    ]);
    let reported = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(reported, expected);
    let written = std::fs::read_dir(&output)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(written, expected, "the output directory is the closed set");
    let effective: Value = serde_json::from_slice(
        &std::fs::read(Path::new(&output).join("effective-contract.v1alpha1.schema.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        effective["$id"],
        "https://id.registrystack.org/schemas/adapter/effective-contract/effective-contract.v1alpha1.schema.json"
    );
    assert_eq!(effective["additionalProperties"], false);
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

/// The minimal fixture project's directory.
fn minimal_project_directory() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/minimal")
        .to_str()
        .unwrap()
        .to_owned()
}

/// The sha256 uri of one file's bytes as read.
fn pinned_digest(path: &Path) -> String {
    registry_platform_config::sha256_uri(&std::fs::read(path).unwrap())
}

// --- the project argument accepts the directory form ---

/// The project argument accepts the project's directory: `project.yaml`
/// and the files beside it are read from there, exactly as for the file
/// form.
#[test]
fn check_accepts_the_project_directory() {
    let (exit, report, stderr) = run_json(&["check", &minimal_project_directory()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["filesChecked"], 6);
    assert_eq!(report["diagnostics"], json!([]));
}

/// A directory that carries no `project.yaml` is the same operational
/// failure as a missing project file: the file the run needs is absent.
#[test]
fn a_directory_without_a_project_yaml_is_an_operational_failure() {
    let root = tempfile::tempdir().unwrap();
    let empty = root.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let (exit, report, _) = run_json(&["check", empty.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
    assert_eq!(report["status"], "operational-failure", "{report}");
    assert_eq!(report["diagnostics"][0]["code"], "adapterctl.io-failure");
    assert!(
        report["diagnostics"][0]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("empty/project.yaml")),
        "{report}"
    );
}

// --- `project lock` ---

/// The directory of one copied project path.
fn directory_of(project: &str) -> String {
    Path::new(project)
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

/// The project text after one lock run over its directory.
fn lock_directory(directory: &str) -> (ExitCode, Value, Vec<u8>) {
    run_json(&["project", "lock", directory])
}

/// `project lock` rewrites a stale digest pin from the files beside the
/// project, reports the pin it rewrote, and the repaired project then
/// checks green under the same reader and checks as `check`.
#[test]
fn project_lock_repairs_a_stale_digest_pin_and_the_project_then_checks_green() {
    let pack = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal/pack.yaml");
    let stale = format!("  digest: {}", pinned_digest(&pack));
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            &stale,
            "  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
    });
    let directory = directory_of(&project);
    let (exit, report, stderr) = lock_directory(&directory);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["command"], "project lock");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["profile"], "unchanged");
    assert_eq!(report["pack"], "updated");
    let rewritten = std::fs::read_to_string(&project).unwrap();
    assert!(
        rewritten.contains(&stale),
        "the lock must restore the pack digest pin: {rewritten}"
    );
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["filesChecked"], 6);
}

/// A lock over an already pinned project reports both artifacts unchanged
/// and writes nothing.
#[test]
fn project_lock_of_a_fresh_project_writes_nothing() {
    let (_root, project) = mutated_project(|_| {});
    let directory = directory_of(&project);
    let before = std::fs::read(&project).unwrap();
    let (exit, report, _) = lock_directory(&directory);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["profile"], "unchanged");
    assert_eq!(report["pack"], "unchanged");
    assert_eq!(
        std::fs::read(&project).unwrap(),
        before,
        "a fresh project must not be rewritten"
    );
}

/// A pin is a byte digest: the lock pins whatever bytes the artifact
/// carries, even bytes the reader would refuse, because deciding whether
/// an artifact is a good one is `check`'s business. The repinned project
/// then refuses with the reader's code alone, no pin diagnostic beside it.
#[test]
fn project_lock_pins_bytes_a_reader_would_refuse() {
    let profile = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal/profile.yaml");
    let stale = format!("  digest: {}", pinned_digest(&profile));
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("profile.yaml"),
            "problemEnvelope:",
            "conformanceUnknown: x\nproblemEnvelope:",
        );
        edit(
            &root.join("project.yaml"),
            &stale,
            "  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
    });
    let directory = directory_of(&project);
    let (exit, report, _) = lock_directory(&directory);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["profile"], "updated");
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "config.unknown-key");
    let diagnostics = report["diagnostics"].as_array().unwrap();
    assert_eq!(
        diagnostics.len(),
        1,
        "the pin must not add a diagnostic beside the reader's: {report}"
    );
}

/// The lock accepts the `project.yaml` file form as well as the directory
/// form.
#[test]
fn project_lock_accepts_the_project_file_form() {
    let pack = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal/pack.yaml");
    let stale = format!("  digest: {}", pinned_digest(&pack));
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            &stale,
            "  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
    });
    let (exit, report, _) = lock_directory(&project);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["pack"], "updated");
}

/// A lock whose pack file is missing is an operational failure naming the
/// absent file, and nothing is written.
#[test]
fn project_lock_with_a_missing_pack_is_an_operational_failure() {
    let (_root, project) = mutated_project(|root| {
        std::fs::remove_file(root.join("pack.yaml")).unwrap();
    });
    let directory = directory_of(&project);
    let before = std::fs::read(&project).unwrap();
    let (exit, report, _) = lock_directory(&directory);
    assert_eq!(exit, ExitCode::from(3), "{report}");
    assert_eq!(report["status"], "operational-failure", "{report}");
    assert_eq!(report["diagnostics"][0]["code"], "adapterctl.io-failure");
    assert!(
        report["diagnostics"][0]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("pack.yaml")),
        "{report}"
    );
    assert_eq!(std::fs::read(&project).unwrap(), before);
}

/// A project folder that holds no pack or profile beside it refuses with
/// the missing file named and the flag to pass, from every command that
/// reads the pair: the project does not say where its pack lives.
#[test]
fn a_missing_pack_or_profile_names_the_file_and_the_flag() {
    for (file, flag) in [("pack.yaml", "--pack"), ("profile.yaml", "--profile")] {
        let (_root, project) = mutated_project(|root| {
            std::fs::remove_file(root.join(file)).unwrap();
        });
        for command in [
            vec!["check", project.as_str()],
            vec!["compile", project.as_str()],
            vec!["fixtures", "replay", project.as_str()],
            vec!["project", "lock", project.as_str()],
        ] {
            let (exit, report, _) = run_json(&command);
            assert_eq!(exit, ExitCode::from(3), "{command:?}: {report}");
            let diagnostic = &report["diagnostics"][0];
            assert_eq!(diagnostic["code"], "adapterctl.io-failure");
            assert!(
                diagnostic["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(file)),
                "{command:?}: {report}"
            );
            let message = diagnostic["message"].as_str().unwrap_or_default();
            assert!(
                message.contains(file) && message.contains(flag),
                "{command:?}: {report}"
            );
        }
    }
}

/// The committed example folder holds only the project: a bare `check` names
/// the missing pack and the flag, and with the maintained pair it passes.
#[test]
fn the_example_folder_needs_its_pack_and_profile_by_flag() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let example = root.join("products/adapter/examples/dhis2-tracker/project.yaml");
    let example = example.to_str().unwrap();

    let (exit, report, _) = run_json(&["check", example]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        message.contains("profile.yaml") && message.contains("--profile"),
        "{report}"
    );

    let profile = root.join("products/adapter/profiles/breg-records/profile.yaml");
    let (exit, report, _) = run_json(&["check", example, "--profile", profile.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        message.contains("pack.yaml") && message.contains("--pack"),
        "{report}"
    );

    let pack = root.join("products/adapter/packs/dhis2-tracker/pack.yaml");
    let (exit, report, _) = run_json(&[
        "check",
        example,
        "--profile",
        profile.to_str().unwrap(),
        "--pack",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
}

/// A project the reader refuses is a domain refusal carrying the reader's
/// findings, and nothing is written.
#[test]
fn project_lock_refuses_a_project_that_does_not_decode_and_writes_nothing() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            "kind: AdapterProject",
            "kind: AdapterImagine",
        );
    });
    let directory = directory_of(&project);
    let before = std::fs::read(&project).unwrap();
    let (exit, report, _) = lock_directory(&directory);
    assert_refused(exit, &report, "config.wrong-kind");
    assert_eq!(std::fs::read(&project).unwrap(), before);
}

/// A project whose pinned artifact blocks are not in the line form the
/// lock rewrites refuses with the layout code at the pin, and nothing is
/// written.
#[test]
fn project_lock_refuses_a_project_it_cannot_rewrite() {
    let profile = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal/profile.yaml");
    let pinned = pinned_digest(&profile);
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("project.yaml"),
            &format!("profile:\n  id: case-api\n  version: 1.0.0\n  digest: {pinned}"),
            &format!("profile: {{id: case-api, version: 1.0.0, digest: {pinned}}}"),
        );
    });
    let directory = directory_of(&project);
    let before = std::fs::read(&project).unwrap();
    let (exit, report, _) = lock_directory(&directory);
    assert_refused(exit, &report, "adapterctl.project-lock-layout");
    assert_eq!(report["diagnostics"][0]["path"], "/profile/digest");
    assert_eq!(std::fs::read(&project).unwrap(), before);
}

/// A lock pins the profile and pack given by `--profile` and `--pack` even
/// when neither sits beside the project, and the project then checks green
/// when check reads the same artifacts.
#[test]
fn project_lock_pins_the_artifacts_given_by_flag() {
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    copy_fs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal"),
        &project_dir,
    );
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::rename(
        project_dir.join("profile.yaml"),
        elsewhere.join("profile.yaml"),
    )
    .unwrap();
    // The pack moves with its digest-pinned scripts: a pin resolves beside
    // the pack document, wherever the flag names it.
    std::fs::rename(project_dir.join("pack.yaml"), elsewhere.join("pack.yaml")).unwrap();
    std::fs::rename(project_dir.join("scripts"), elsewhere.join("scripts")).unwrap();
    let project = project_dir
        .join("project.yaml")
        .to_str()
        .unwrap()
        .to_owned();
    let pack_file = elsewhere.join("pack.yaml");
    let profile_file = elsewhere.join("profile.yaml");
    let stale = format!("  digest: {}", pinned_digest(&pack_file));
    edit(
        Path::new(&project),
        &stale,
        "  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    let (exit, report, _) = run_json(&[
        "project",
        "lock",
        &project,
        "--profile",
        profile_file.to_str().unwrap(),
        "--pack",
        pack_file.to_str().unwrap(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["profile"], "unchanged");
    assert_eq!(report["pack"], "updated");
    let rewritten = std::fs::read_to_string(&project).unwrap();
    assert!(
        rewritten.contains(&stale),
        "the lock must pin the flagged pack's digest: {rewritten}"
    );
    let (exit, report, _) = run_json(&[
        "check",
        &project,
        "--profile",
        profile_file.to_str().unwrap(),
        "--pack",
        pack_file.to_str().unwrap(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
}

/// An edited script is repinned by `project lock`: the pack's inventory
/// digest line is rewritten from the file beside the pack, the project's
/// pack pin follows the rewritten pack bytes, and the project then checks
/// green. One edit, one command, no hand-pasted digests.
#[test]
fn project_lock_repins_an_edited_script_and_the_project_then_checks_green() {
    let fixture_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal/scripts/map.rhai");
    let old_line = format!("    digest: {}", pinned_digest(&fixture_script));
    let mut edited_digest = String::new();
    let (_root, project) = mutated_project(|root| {
        let script = root.join("scripts/map.rhai");
        let contents = std::fs::read_to_string(&script).unwrap();
        std::fs::write(&script, format!("{contents}\n// edited after pinning\n")).unwrap();
        edited_digest = registry_platform_config::sha256_uri(&std::fs::read(&script).unwrap());
    });
    let copy = Path::new(&project).parent().unwrap().to_path_buf();
    let directory = directory_of(&project);
    let (exit, report, stderr) = lock_directory(&directory);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["profile"], "unchanged", "{report}");
    assert_eq!(report["inventory"], "updated", "{report}");
    assert_eq!(report["pack"], "updated", "{report}");
    let rewritten = std::fs::read_to_string(copy.join("pack.yaml")).unwrap();
    assert!(
        rewritten.contains(&format!("    digest: {edited_digest}")),
        "the lock must repin the script: {rewritten}"
    );
    assert!(
        !rewritten.contains(&old_line),
        "the stale script pin must be gone: {rewritten}"
    );
    // The project's pack pin follows the pack bytes as they now sit, so
    // the check after the lock is green.
    let pin = format!("  digest: {}", pinned_digest(&copy.join("pack.yaml")));
    let rewritten = std::fs::read_to_string(&project).unwrap();
    assert!(
        rewritten.contains(&pin),
        "the pack pin must follow the rewritten pack: {rewritten}"
    );
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["filesChecked"], 6);
}

/// A lock whose pack pins a file that is missing refuses with the pack's
/// digest-pin code at the inventory entry and writes nothing: there is
/// nothing to hash, so no pin can follow.
#[test]
fn project_lock_with_a_missing_script_file_refuses_and_writes_nothing() {
    let (_root, project) = mutated_project(|root| {
        std::fs::remove_file(root.join("scripts/map.rhai")).unwrap();
    });
    let copy = Path::new(&project).parent().unwrap().to_path_buf();
    let directory = directory_of(&project);
    let before_project = std::fs::read(&project).unwrap();
    let before_pack = std::fs::read(copy.join("pack.yaml")).unwrap();
    let (exit, report, _) = lock_directory(&directory);
    assert_refused(exit, &report, "adapter.pack.digest-pin-required");
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "adapter.pack.digest-pin-required")
        .unwrap();
    assert_eq!(diagnostic["path"], "/scripts/0", "{report}");
    assert_eq!(
        diagnostic["message"], "the pinned file is missing",
        "{diagnostic}"
    );
    assert_eq!(std::fs::read(&project).unwrap(), before_project);
    assert_eq!(std::fs::read(copy.join("pack.yaml")).unwrap(), before_pack);
}

/// An inventory whose digest pins are not in the block form the lock
/// rewrites refuses at the section and writes nothing, even though the
/// project's own pins could be rewritten: a run is all-or-nothing.
#[test]
fn project_lock_refuses_an_inventory_it_cannot_rewrite() {
    let fixture_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal/scripts/map.rhai");
    let pinned = pinned_digest(&fixture_script);
    let (_root, project) = mutated_project(|root| {
        let script = root.join("scripts/map.rhai");
        let contents = std::fs::read_to_string(&script).unwrap();
        std::fs::write(&script, format!("{contents}\n// edited after pinning\n")).unwrap();
        let flow = format!("  - {{path: scripts/map.rhai, digest: {pinned}}}");
        edit(
            &root.join("pack.yaml"),
            &format!("  - path: scripts/map.rhai\n    digest: {pinned}"),
            &flow,
        );
    });
    let copy = Path::new(&project).parent().unwrap().to_path_buf();
    let directory = directory_of(&project);
    let before_project = std::fs::read(&project).unwrap();
    let before_pack = std::fs::read(copy.join("pack.yaml")).unwrap();
    let (exit, report, _) = lock_directory(&directory);
    assert_refused(exit, &report, "adapterctl.project-lock-layout");
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "adapterctl.project-lock-layout")
        .unwrap();
    assert_eq!(diagnostic["path"], "/scripts", "{report}");
    assert_eq!(std::fs::read(&project).unwrap(), before_project);
    assert_eq!(std::fs::read(copy.join("pack.yaml")).unwrap(), before_pack);
}

/// A pack that does not decode cannot name its inventory, so the lock
/// warns that the inventory pins were not rewritten and still pins the
/// pack bytes the project names: judging the pack is `check`'s business,
/// and the pins stay honest about the bytes on disk.
#[test]
fn project_lock_warns_when_the_pack_does_not_decode_and_still_pins_the_bytes() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("pack.yaml"),
            "kind: AdapterPack",
            "kind: AdapterPack\nconformanceUnknown: x",
        );
    });
    let copy = Path::new(&project).parent().unwrap().to_path_buf();
    let directory = directory_of(&project);
    let (exit, report, _) = lock_directory(&directory);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["inventory"], "unchanged", "{report}");
    assert_eq!(report["pack"], "updated", "{report}");
    let diagnostics = report["diagnostics"].as_array().unwrap();
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic["code"] == "adapterctl.pack-not-decoded"
                && diagnostic["severity"] == "warning"
        }),
        "{report}"
    );
    let pin = format!("  digest: {}", pinned_digest(&copy.join("pack.yaml")));
    let rewritten = std::fs::read_to_string(&project).unwrap();
    assert!(
        rewritten.contains(&pin),
        "the pack bytes must be pinned as they sit: {rewritten}"
    );
}

/// A full runtime configuration for the minimal project's operation, with
/// one `${NAME}` expression at `oidc.audience` (a plain text member) and
/// another at `audit.retentionDays` when `retention` says so.
fn runtime_with_expressions(retention: &str) -> String {
    format!(
        "apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: case-deployment
endpoints:
  - endpoint: case-api
    baseUrl: https://cases.example.invalid
    credential:
      type: oauth2-client-credentials
      tokenEndpoint: https://token.example.invalid/token
      clientIdRef: secret:env/CASE_API_CLIENT_ID
      clientSecretRef: secret:env/CASE_API_CLIENT_SECRET
      credentialPlacement: basic-header
      maximumCacheSeconds: 3600
listener:
  bind: 127.0.0.1:8080
database:
  runtimeUrlRef: secret:env/CASE_DB_RUNTIME
  migrationUrlRef: secret:env/CASE_DB_MIGRATION
oidc:
  issuer: https://issuer.example.invalid
  audience: ${{ADAPTERCTL_TEST_AUDIENCE:-case-api}}
allowedClients:
  - case-portal
allowedPrivateCidrs:
  - 10.0.0.0/8
audit:
  retentionDays: {retention}
"
    )
}

/// Write the runtime file beside the copied project and return its path.
fn write_runtime(root: &Path, retention: &str) -> String {
    let path = root.join("runtime.yaml");
    std::fs::write(&path, runtime_with_expressions(retention)).unwrap();
    path.to_str().unwrap().to_owned()
}

/// `anonymousHttps` is a named security acknowledgement. Omission remains
/// closed at the policy layer, while null, booleans, and unknown strings are
/// refused by the shared configuration reader with its typed diagnostics.
#[test]
fn anonymous_https_acknowledgement_has_strict_reader_diagnostics() {
    for (yaml, code) in [
        ("    anonymousHttps: null\n", "config.null-value"),
        ("    anonymousHttps: false\n", "config.expected-string"),
        ("    anonymousHttps: accepted\n", "config.unknown-variant"),
    ] {
        let (_root, project) = mutated_project(|root| {
            let runtime = runtime_with_expressions("90").replace(
                "    baseUrl: https://cases.example.invalid\n",
                &format!("    baseUrl: https://cases.example.invalid\n{yaml}"),
            );
            std::fs::write(root.join("runtime.yaml"), runtime).unwrap();
        });
        let runtime = _root.path().join("minimal").join("runtime.yaml");
        let (exit, report, _) =
            run_json(&["check", &project, "--runtime", runtime.to_str().unwrap()]);
        assert_refused(exit, &report, code);
        let diagnostic = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|diagnostic| diagnostic["code"] == code)
            .unwrap();
        assert_eq!(diagnostic["path"], "/endpoints/0/anonymousHttps");
    }
}

/// Without `--environment` the runtime file is checked the way the runtime
/// reads it before the environment exists: an expression is checked by
/// syntax and position only, and the text member it fills accepts the
/// stand-in (CFG-CHECK-1). No variable is read, so no diagnostic names one.
#[test]
fn the_runtime_file_without_environment_accepts_a_deferred_expression() {
    let (_root, project) = mutated_project(|root| {
        write_runtime(root, "90");
    });
    let runtime = _root.path().join("minimal").join("runtime.yaml");
    let (exit, report, _) = run_json(&["check", &project, "--runtime", runtime.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["diagnostics"], json!([]), "{report}");
    assert_eq!(report["filesChecked"], 7);
}

/// Without `--environment` an expression in a non-text member is still
/// refused: substitution fills text values only, and the refusal's fix is
/// to write the value or template the whole file (CFG-SEC-2).
#[test]
fn the_runtime_file_without_environment_refuses_an_expression_in_an_integer_member() {
    let (_root, project) = mutated_project(|root| {
        write_runtime(root, "\"${ADAPTERCTL_TEST_RETENTION}\"");
    });
    let runtime = _root.path().join("minimal").join("runtime.yaml");
    let (exit, report, _) = run_json(&["check", &project, "--runtime", runtime.to_str().unwrap()]);
    assert_refused(exit, &report, "config.expected-integer");
    let diagnostics = report["diagnostics"].as_array().unwrap();
    let integer = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "config.expected-integer")
        .unwrap();
    assert_eq!(integer["path"], "/audit/retentionDays", "{report}");
    assert_eq!(
        integer["suggestedAction"],
        "Write the value, or template the whole file."
    );
}

/// A member ending in `Ref` carries a secret reference, so an expression
/// there is refused by position before any variable is read, with or
/// without `--environment` (CFG-SEC-2).
#[test]
fn the_runtime_file_refuses_an_expression_in_a_reference_member() {
    let (_root, project) = mutated_project(|root| {
        let runtime = runtime_with_expressions("90").replace(
            "      clientSecretRef: secret:env/CASE_API_CLIENT_SECRET\n",
            "      clientSecretRef: \"${ADAPTERCTL_TEST_CA}\"\n",
        );
        std::fs::write(root.join("runtime.yaml"), runtime).unwrap();
    });
    let runtime = _root.path().join("minimal").join("runtime.yaml");
    let (exit, report, _) = run_json(&["check", &project, "--runtime", runtime.to_str().unwrap()]);
    assert_refused(exit, &report, "config.substitution-not-allowed");
    let diagnostics = report["diagnostics"].as_array().unwrap();
    let reference = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "config.substitution-not-allowed")
        .unwrap();
    assert_eq!(
        reference["path"], "/endpoints/0/credential/clientSecretRef",
        "{report}"
    );
}

/// A runtime file carrying the removed `caBundleRef` key is refused with
/// the reader's removed-key diagnostic at the key, naming the
/// `tlsTrustProfile` replacement (CFG-CHANGE-2).
#[test]
fn the_runtime_file_refuses_the_removed_ca_bundle_ref_key() {
    let (_root, project) = mutated_project(|root| {
        let runtime = runtime_with_expressions("90").replace(
            "    baseUrl: https://cases.example.invalid\n",
            "    baseUrl: https://cases.example.invalid\n    caBundleRef: secret:file/households-ca.pem\n",
        );
        std::fs::write(root.join("runtime.yaml"), runtime).unwrap();
    });
    let runtime = _root.path().join("minimal").join("runtime.yaml");
    let (exit, report, _) = run_json(&["check", &project, "--runtime", runtime.to_str().unwrap()]);
    assert_refused(exit, &report, "config.removed-key");
    let diagnostics = report["diagnostics"].as_array().unwrap();
    let removed = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "config.removed-key")
        .unwrap();
    assert_eq!(removed["path"], "/endpoints/0/caBundleRef", "{report}");
    assert!(
        removed["suggestedAction"]
            .as_str()
            .is_some_and(|action| action.contains("tlsTrustProfile")),
        "{report}"
    );
}

/// With `--environment` an expression naming an unset variable is refused
/// at the member, naming the variable and never its value (CFG-SEC-2,
/// CFG-SEC-3).
#[test]
fn the_runtime_file_with_environment_refuses_an_unset_variable() {
    let (_root, project) = mutated_project(|root| {
        let runtime = runtime_with_expressions("90").replace(
            "${ADAPTERCTL_TEST_AUDIENCE:-case-api}",
            "${ADAPTERCTL_TEST_UNSET}",
        );
        std::fs::write(root.join("runtime.yaml"), runtime).unwrap();
    });
    let runtime = _root.path().join("minimal").join("runtime.yaml");
    let (exit, report, _) = run_json(&[
        "check",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
        "--environment",
    ]);
    assert_refused(exit, &report, "config.substitution");
    let diagnostics = report["diagnostics"].as_array().unwrap();
    let substitution = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "config.substitution")
        .unwrap();
    assert_eq!(substitution["path"], "/oidc/audience", "{report}");
    assert_eq!(
        substitution["message"],
        "the environment variable ADAPTERCTL_TEST_UNSET is unset or empty"
    );
    assert_eq!(
        substitution["suggestedAction"],
        "Set ADAPTERCTL_TEST_UNSET in the runtime's environment, or write a fallback as ${ADAPTERCTL_TEST_UNSET:-fallback}."
    );
}

/// With `--environment` a set variable fills the member and the check
/// reads every value (CFG-CHECK-1); the value itself is never printed.
#[test]
fn the_runtime_file_with_environment_fills_a_set_variable() {
    let (_root, project) = mutated_project(|root| {
        write_runtime(root, "90");
    });
    let runtime = _root.path().join("minimal").join("runtime.yaml");
    std::env::set_var("ADAPTERCTL_TEST_AUDIENCE", "resolved-audience");
    let (exit, report, stderr) = run_json(&[
        "check",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
        "--environment",
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["diagnostics"], json!([]), "{report}");
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(!stderr.contains("resolved-audience"), "{stderr}");
}

/// `--environment` without a runtime file to read is a usage error: there
/// is nothing to fill.
#[test]
fn environment_without_a_runtime_file_is_a_usage_error() {
    let (exit, report, _) = run_json(&["check", &minimal_project(), "--environment"]);
    assert_eq!(exit, ExitCode::from(2));
    assert_eq!(report["status"], "usage-error");
}

/// An environment expression in an authored file is refused where it is
/// written (CFG-SEC-2): the pin the project carries for the profile adds
/// no diagnostic beside the reader's refusal, and the lock still pins the
/// refused bytes, so the repair is the value, not the pin.
#[test]
fn an_expression_in_an_authored_file_is_refused_where_it_is_written() {
    let (_root, project) = mutated_project(|root| {
        edit(
            &root.join("profile.yaml"),
            "version: ",
            "version: \"${ADAPTERCTL_TEST_VERSION}\" # ",
        );
    });
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "config.substitution-not-allowed");
    let diagnostics = report["diagnostics"].as_array().unwrap();
    assert_eq!(
        diagnostics.len(),
        1,
        "the pin must not add a diagnostic beside the reader's: {report}"
    );
    assert_eq!(diagnostics[0]["path"], "/version", "{report}");
    assert_eq!(
        diagnostics[0]["suggestedAction"],
        "Write the value in the authored file directly."
    );
    let directory = directory_of(&project);
    let (exit, report, _) = lock_directory(&directory);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["profile"], "updated");
}

// ------------------------------------------------------------------------
// GraphQL query files: the pinned file parses and the endpoint's
// operation is one it declares.

/// The valid pinned query the graphql tests use, and its sha256 digest.
const CASES_QUERY: &str =
    "query casesByType($type: String!) {\n  cases(type: $type) {\n    id\n  }\n}\n";
const CASES_QUERY_DIGEST: &str =
    "sha256:47c99d9134c4cd899c5e62082c182d1e396ecde75885af5c1907887c638ce24a";

const CASES_MUTATION: &str =
    "mutation casesByType($type: String!) {\n  cases(type: $type) {\n    id\n  }\n}\n";

/// A query document no parser accepts, and its sha256 digest.
const BROKEN_QUERY: &str = "query casesByType($type: String!) {\n  cases(type: $type)\n";
const BROKEN_QUERY_DIGEST: &str =
    "sha256:107613ff0621aaf624701eca66619eb1cc81c3ba9cc97b3cc7e08e382aa337d2";

/// A copy of the minimal fixture turned into a graphql pack: the pinned
/// query file, a graphql endpoint naming `operation_name`, and the
/// graphql capability, repinned so the project's pack digest matches the
/// edited pack.
fn graphql_project(query: &str, digest: &str, operation_name: &str) -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("minimal");
    copy_fs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal"),
        &copy,
    );
    let query_file = copy.join("queries/cases-by-type.graphql");
    std::fs::create_dir_all(query_file.parent().unwrap()).unwrap();
    std::fs::write(&query_file, query).unwrap();
    edit(
        &copy.join("pack.yaml"),
        "queryFiles: []",
        &format!("queryFiles:\n  - path: queries/cases-by-type.graphql\n    digest: {digest}"),
    );
    edit(
        &copy.join("pack.yaml"),
        "      - id: cases-create\n        idempotentUpstream: true\nrouteTemplates:\n",
        &format!(
            "      - id: cases-create\n        idempotentUpstream: true\n  - id: case-graphql\n    component: graphql\n    authentication:\n      type: none\n    attemptTimeoutMilliseconds: 10000\n    maximumResponseBytes: 1048576\n    operationName: {operation_name}\n    queryFile: queries/cases-by-type.graphql\n    operations:\n      - id: cases-by-type\n        idempotentUpstream: true\n        graphql: query\nrouteTemplates:\n"
        ),
    );
    edit(
        &copy.join("pack.yaml"),
        "    - http\n",
        "    - http\n    - graphql\n",
    );
    let directory = directory_of(copy.join("project.yaml").to_str().unwrap());
    let (exit, report, stderr) = lock_directory(&directory);
    assert_eq!(
        exit,
        ExitCode::SUCCESS,
        "the edited pack must repin: {report} {}",
        String::from_utf8_lossy(&stderr)
    );
    (root, copy.join("project.yaml").to_str().unwrap().to_owned())
}

/// A graphql pack whose pinned query parses and whose endpoint names an
/// operation the file declares checks green, one file more than the
/// minimal fixture.
#[test]
fn a_graphql_pack_whose_operation_is_declared_checks_green() {
    let (_root, project) = graphql_project(CASES_QUERY, CASES_QUERY_DIGEST, "casesByType");
    let (exit, report, stderr) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["filesChecked"], 7, "{report}");
    assert_eq!(report["diagnostics"], json!([]));
}

/// A pinned query file no GraphQL parser accepts refuses at its
/// inventory entry.
#[test]
fn a_query_file_that_does_not_parse_refuses_with_the_query_code() {
    let (_root, project) = graphql_project(BROKEN_QUERY, BROKEN_QUERY_DIGEST, "casesByType");
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.graphql-query-invalid");
    assert_eq!(
        diagnostic_path(&report, "adapter.pack.graphql-query-invalid"),
        "/queryFiles/0",
        "{report}"
    );
}

#[test]
fn an_oversized_sparse_query_file_is_refused_without_reading_its_length() {
    let (_root, project) = graphql_project(CASES_QUERY, CASES_QUERY_DIGEST, "casesByType");
    let query = Path::new(&project)
        .parent()
        .expect("the project has a directory")
        .join("queries/cases-by-type.graphql");
    std::fs::OpenOptions::new()
        .write(true)
        .open(query)
        .expect("the query file opens")
        .set_len(1024 * 1024 * 1024)
        .expect("the sparse length is set");

    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.digest-pin-required");
    assert_eq!(
        diagnostic_path(&report, "adapter.pack.digest-pin-required"),
        "/queryFiles/0",
        "{report}"
    );
}

/// An endpoint naming an operation the pinned query file does not
/// declare refuses at the endpoint's operationName member.
#[test]
fn an_operation_the_query_file_does_not_declare_refuses_with_the_operation_code() {
    let (_root, project) = graphql_project(CASES_QUERY, CASES_QUERY_DIGEST, "missingOperation");
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.graphql-operation-unknown");
    assert_eq!(
        diagnostic_path(&report, "adapter.pack.graphql-operation-unknown"),
        "/endpoints/1/operationName",
        "{report}"
    );
}

#[test]
fn a_graphql_endpoint_without_an_operation_name_is_refused() {
    let (_root, project) = graphql_project(CASES_QUERY, CASES_QUERY_DIGEST, "casesByType");
    let pack = Path::new(&project).with_file_name("pack.yaml");
    edit(&pack, "    operationName: casesByType\n", "");
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(exit, &report, "adapter.pack.graphql-operation-required");
    assert_eq!(
        diagnostic_path(&report, "adapter.pack.graphql-operation-required"),
        "/endpoints/1/operationName",
        "{report}"
    );
}

#[test]
fn a_declared_graphql_kind_must_match_the_pinned_operation() {
    let digest = registry_platform_config::sha256_uri(CASES_MUTATION.as_bytes());
    let (_root, project) = graphql_project(CASES_MUTATION, &digest, "casesByType");
    let (exit, report, _) = run_json(&["check", &project]);
    assert_refused(
        exit,
        &report,
        "adapter.pack.graphql-operation-kind-mismatch",
    );
    assert_eq!(
        diagnostic_path(&report, "adapter.pack.graphql-operation-kind-mismatch"),
        "/endpoints/1/operations/0/graphql",
        "{report}"
    );
}
