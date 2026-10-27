use std::{fs, path::Path, process::Command};

fn project(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples")
        .join(name)
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create copied project directory");
    for entry in fs::read_dir(from).expect("read source project") {
        let entry = entry.expect("project entry");
        let destination = to.join(entry.file_name());
        if entry.file_type().expect("project entry type").is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy project file");
        }
    }
}

#[test]
fn explain_connects_a_real_definition_to_its_source_operation_facts_and_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg("explain")
        .arg(project("fhir"))
        .output()
        .expect("run evidencectl explain");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}");
    assert!(stderr.is_empty(), "{stderr}");

    assert!(stdout
        .contains("Definition fhir-coverage-status: urn:example:requirement:coverage-record:v1"));
    assert!(stdout.contains(
        "Source coverage-record: http-json GET /Coverage/{coverage_id}; connection fhir-read-through"
    ));
    assert!(stdout.contains("Prepare: generated; extract: Function extract-coverage"));
    assert!(stdout.contains("Facts: beneficiary-reference, status"));
    assert!(stdout.contains("Limits: 30000 ms attempt, 8 concurrent, 65536 bytes response"));
    assert!(stdout.contains("Derive: Function derive-coverage-status"));
    assert!(stdout.contains("Outputs: coverage-record-reports-active"));
}

#[test]
fn malformed_project_is_refused_without_printing_private_source_values() {
    const CANARY: &str = "PRIVATE-SOURCE-VALUE-MUST-NOT-LEAK";
    let temporary = tempfile::tempdir().expect("temporary project");
    copy_tree(&project("fhir"), temporary.path());
    let manifest = temporary.path().join("evidence.yaml");
    let authored = fs::read_to_string(&manifest).expect("read project manifest");
    let malformed = authored.replacen(
        "    connection: fhir-read-through\n",
        &format!("    connection: fhir-read-through\n    privateSourceValue: {CANARY}\n"),
        1,
    );
    assert_ne!(malformed, authored, "fixture mutation must apply");
    fs::write(&manifest, malformed).expect("write malformed project manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg("explain")
        .arg(temporary.path())
        .output()
        .expect("run evidencectl explain");
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(1), "{printed}");
    assert!(
        printed.contains("Evidence project explain: refused"),
        "{printed}"
    );
    assert!(!printed.contains(CANARY), "{printed}");
    assert!(!printed.contains("Source coverage-record"), "{printed}");
}

#[test]
fn explain_json_reports_each_definitions_validity_seconds() {
    let temporary = tempfile::tempdir().expect("temporary project");
    copy_tree(&project("standalone"), temporary.path());
    let manifest = temporary.path().join("evidence.yaml");
    let authored = fs::read_to_string(&manifest).expect("read project manifest");
    let changed = authored.replacen("validitySeconds: 300", "validitySeconds: 900", 1);
    assert_ne!(changed, authored, "fixture mutation must apply");
    fs::write(&manifest, changed).expect("write project manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["--format", "json", "explain"])
        .arg(temporary.path())
        .output()
        .expect("run evidencectl explain");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("explain JSON report");
    let definitions = report["assertionDefinitions"]
        .as_array()
        .unwrap_or_else(|| panic!("assertionDefinitions array in {stdout}"));
    assert!(definitions.len() >= 2, "{stdout}");
    let validities: Vec<_> = definitions
        .iter()
        .map(|definition| definition["validitySeconds"].as_u64())
        .collect();
    assert_eq!(validities[0], Some(900), "{validities:?}");
    assert!(
        validities[1..]
            .iter()
            .all(|validity| *validity == Some(300)),
        "{validities:?}"
    );
}
