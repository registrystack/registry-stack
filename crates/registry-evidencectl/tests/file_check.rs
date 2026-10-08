//! `evidencectl check --file`: one tooling file, checked on its own.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

/// Every format the command reads, with its registered example.
const EXAMPLES: [(&str, &str); 7] = [
    (
        "evidence/client-profile",
        "evidence/examples/client-profile/client-profile.json",
    ),
    (
        "evidence/client-contracts",
        "evidence/examples/client-contracts/evidence.contracts.json",
    ),
    (
        "evidence/dev-state",
        "evidence/examples/formats/dev-session/.evidence/dev/state.json",
    ),
    (
        "evidence/source-import-journal",
        "evidence/examples/formats/source-imports/.evidence/source-imports/transaction.json",
    ),
    (
        "evidence/source-import-state",
        "evidence/examples/formats/source-imports/.evidence/source-imports/state.json",
    ),
    (
        "evidence/source-resolution",
        "evidence/examples/formats/source-resolutions.json",
    ),
    (
        "breg/evidence-source-export",
        "breg/examples/formats/source-export.json",
    ),
];

fn example(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products")
        .join(relative)
}

fn check_file(file: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg("check")
        .arg("--file")
        .arg(file)
        .args(extra)
        .output()
        .expect("run evidencectl")
}

fn json_report(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "JSON mode wrote human text: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("a JSON report")
}

/// The example with one member the format does not define added at its root.
fn with_unknown_member(format: &str, relative: &str, directory: &Path) -> PathBuf {
    let mut document: Value =
        serde_json::from_slice(&fs::read(example(relative)).expect("example")).expect("JSON");
    document["unexpectedMember"] = Value::Bool(true);
    let file = directory.join(format.replace('/', "-") + ".json");
    fs::write(&file, serde_json::to_vec_pretty(&document).expect("JSON")).expect("write");
    file
}

#[test]
fn every_registered_example_passes_in_human_output() {
    for (format, relative) in EXAMPLES {
        let output = check_file(&example(relative), &[]);
        assert_eq!(output.status.code(), Some(0), "{format}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.starts_with("Check passed."), "{format}: {stdout}");
        assert!(output.stderr.is_empty(), "{format}");
    }
}

#[test]
fn every_registered_example_passes_in_json_output() {
    for (format, relative) in EXAMPLES {
        let output = check_file(&example(relative), &["--format", "json"]);
        assert_eq!(output.status.code(), Some(0), "{format}");
        let report = json_report(&output);
        assert_eq!(report["ok"], true, "{format}");
        assert_eq!(report["command"], "check", "{format}");
        assert_eq!(report["status"], "complete", "{format}");
        assert_eq!(report["kind"], "EvidenceCtlReport", "{format}");
        assert_eq!(report["diagnostics"], Value::Array(Vec::new()), "{format}");
    }
}

#[test]
fn a_file_with_a_member_its_format_does_not_define_is_refused() {
    let directory = tempfile::tempdir().expect("directory");
    for (format, relative) in EXAMPLES {
        let file = with_unknown_member(format, relative, directory.path());

        let human = check_file(&file, &[]);
        assert_eq!(human.status.code(), Some(1), "{format}");
        assert!(human.stdout.is_empty(), "{format}");
        let stderr = String::from_utf8_lossy(&human.stderr);
        assert!(
            stderr.starts_with("evidencectl check refused the file."),
            "{format}: {stderr}"
        );
        assert!(!stderr.contains("unexpectedMember: true"), "{format}");

        let json = check_file(&file, &["--format", "json"]);
        assert_eq!(json.status.code(), Some(1), "{format}");
        let report = json_report(&json);
        assert_eq!(report["ok"], false, "{format}");
        assert_eq!(report["status"], "refused", "{format}");
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(|diagnostics| !diagnostics.is_empty()),
            "{format}"
        );
    }
}

#[test]
fn a_file_of_no_known_format_is_refused_naming_the_formats() {
    let directory = tempfile::tempdir().expect("directory");
    for (name, text) in [
        (
            "unknown-kind.json",
            r#"{"apiVersion": "id.registrystack.org/formats/other/v1", "kind": "Other"}"#,
        ),
        ("no-kind.json", r#"{"name": "something"}"#),
    ] {
        let file = directory.path().join(name);
        fs::write(&file, text).expect("write");

        let human = check_file(&file, &[]);
        assert_eq!(human.status.code(), Some(1), "{name}");
        let stderr = String::from_utf8_lossy(&human.stderr);
        assert!(
            stderr.contains("evidence.check.unknown-format"),
            "{name}: {stderr}"
        );
        assert!(
            stderr.contains("EvidenceSourceResolution"),
            "{name}: {stderr}"
        );

        let json = check_file(&file, &["--format", "json"]);
        assert_eq!(json.status.code(), Some(1), "{name}");
        let report = json_report(&json);
        assert_eq!(report["status"], "refused", "{name}");
        assert_eq!(
            report["diagnostics"][0]["code"], "evidence.check.unknown-format",
            "{name}"
        );
    }
}

#[test]
fn a_file_that_is_not_a_document_is_refused_by_the_reader() {
    let directory = tempfile::tempdir().expect("directory");
    let file = directory.path().join("broken.json");
    fs::write(&file, "{ this is not a document").expect("write");

    let human = check_file(&file, &[]);
    assert_eq!(human.status.code(), Some(1));

    let json = check_file(&file, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(1));
    let report = json_report(&json);
    assert_eq!(report["status"], "refused");
    assert!(report["diagnostics"][0]["code"]
        .as_str()
        .is_some_and(|code| code.starts_with("yaml.")));
}

#[test]
fn a_file_that_cannot_be_read_is_an_operational_failure() {
    let directory = tempfile::tempdir().expect("directory");
    let missing = directory.path().join("absent.json");

    let human = check_file(&missing, &[]);
    assert_eq!(human.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(
        stderr.starts_with("evidencectl check could not check the file."),
        "{stderr}"
    );

    let json = check_file(&missing, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(3));
    let report = json_report(&json);
    assert_eq!(report["ok"], false);
    assert_eq!(report["status"], "operational-failure");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidence.check.file-unreadable"
    );
}

#[test]
fn a_file_is_not_checked_together_with_a_project_or_a_target() {
    let file = example(EXAMPLES[5].1);
    for extra in [
        vec!["project"],
        vec!["--target", "target"],
        vec!["--production"],
    ] {
        let output = check_file(&file, &extra);
        assert_eq!(output.status.code(), Some(2), "{extra:?}");
    }
}

#[test]
fn check_without_a_project_or_a_file_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg("check")
        .output()
        .expect("run evidencectl");
    assert_eq!(output.status.code(), Some(2));
}
