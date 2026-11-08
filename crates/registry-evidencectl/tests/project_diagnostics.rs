//! Process-level tests for the diagnostics an authoring project that cannot
//! be read, or whose Adapter pack is wrong, gives an adopter: which file to
//! open and what to change.

use std::{fs, path::Path, process::Command};

use serde_json::Value;

fn run(command: &str, project: &Path) -> (Option<i32>, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["--format", "json", command])
        .arg(project)
        .output()
        .expect("run evidencectl");
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), report)
}

fn first_diagnostic(report: &Value) -> &Value {
    &report["diagnostics"][0]
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create copied directory");
    for entry in fs::read_dir(from).expect("read source directory") {
        let entry = entry.expect("directory entry");
        let destination = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy file");
        }
    }
}

fn standalone_copy() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().expect("temporary project");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/examples/standalone"),
        temporary.path(),
    );
    temporary
}

const PACK: &str = "adapter-packs/synthetic-register/pack.yaml";

#[test]
fn a_directory_without_evidence_yaml_is_refused_naming_the_path_given() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("old-layout");
    fs::create_dir(&project).unwrap();
    for command in ["check", "test"] {
        let (code, report) = run(command, &project);
        assert_eq!(code, Some(1), "{command}: {report}");
        let diagnostic = first_diagnostic(&report);
        assert_eq!(diagnostic["code"], "evidence.project.not-found", "{report}");
        let shown = report.to_string();
        assert!(
            diagnostic["source"]["file"]
                .as_str()
                .is_some_and(|file| file.starts_with(project.to_str().unwrap())
                    && file.ends_with("evidence.yaml")),
            "{shown}"
        );
        assert!(!shown.contains("snapshot"), "{shown}");
        let action = diagnostic["suggestedAction"].as_str().unwrap();
        assert!(action.contains("evidencectl init"), "{action}");
        if command == "test" {
            // `test` also runs a deployment directory, which it knows by its
            // runtime.yaml, so the action names that shape too.
            assert!(action.contains("runtime.yaml"), "{action}");
        }
    }
}

#[test]
fn an_unparseable_pack_is_refused_at_the_pack_file() {
    let project = standalone_copy();
    fs::write(project.path().join(PACK), "apiVersion: [unterminated\n").unwrap();
    let (code, report) = run("check", project.path());
    assert_eq!(code, Some(1), "{report}");
    let diagnostic = first_diagnostic(&report);
    assert_ne!(diagnostic["code"], "evidence.check.failed", "{report}");
    assert!(
        diagnostic["source"]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with(PACK)),
        "{report}"
    );
}

#[test]
fn a_pack_with_an_unknown_key_is_refused_at_that_key() {
    let project = standalone_copy();
    let path = project.path().join(PACK);
    let authored = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        authored.replacen("{\n", "{\n  \"bogusKey\": 1,\n", 1),
    )
    .unwrap();
    let (code, report) = run("check", project.path());
    assert_eq!(code, Some(1), "{report}");
    let diagnostic = first_diagnostic(&report);
    assert_ne!(diagnostic["code"], "evidence.check.failed", "{report}");
    assert_eq!(diagnostic["path"], "/bogusKey", "{report}");
    assert!(
        diagnostic["source"]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with(PACK)),
        "{report}"
    );
}

#[test]
fn an_unknown_source_route_is_refused_at_the_route_naming_the_declared_ones() {
    let project = standalone_copy();
    let path = project.path().join("evidence.yaml");
    let authored = fs::read_to_string(&path).unwrap();
    assert!(authored.contains("route: person\n"));
    fs::write(
        &path,
        authored.replacen("route: person\n", "route: no-such-route\n", 1),
    )
    .unwrap();
    let (code, report) = run("check", project.path());
    assert_eq!(code, Some(1), "{report}");
    let diagnostic = first_diagnostic(&report);
    assert_eq!(
        diagnostic["code"], "evidence.pack.route-missing",
        "{report}"
    );
    assert_eq!(
        diagnostic["path"], "/sources/person-record/route",
        "{report}"
    );
    assert!(
        diagnostic["source"]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("evidence.yaml")),
        "{report}"
    );
    let text = diagnostic.to_string();
    for needle in ["no-such-route", "person", "licence", "parents"] {
        assert!(text.contains(needle), "missing {needle}: {text}");
    }
}
