#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use serde_json::Value;

fn evidencectl(project: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .arg("--project")
        .arg(project)
        .output()
        .expect("run evidencectl")
}

fn write_project(project: &Path, _definition: &str) {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/examples/standalone");
    for file in ["evidence.yaml", "local-target.yaml", "dev-authority.yaml"] {
        fs::copy(source.join(file), project.join(file)).expect("normalized project fixture");
    }
    let path = project.join("dev-authority.yaml");
    let mut authority: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    authority["accessProfiles"] = serde_json::json!({});
    fs::write(path, serde_norway::to_string(&authority).unwrap()).unwrap();
}

/// Declare complete normalized authority in the fixture, then inspect it through the real CLI.
fn declare_profile(project: &Path, id: &str, definitions: &[&str]) -> Output {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/standalone/dev-authority.yaml");
    let template: Value = serde_norway::from_slice(&fs::read(source).unwrap()).unwrap();
    let path = project.join("dev-authority.yaml");
    let mut authority: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut profile = template["accessProfiles"]["standalone-service"].clone();
    profile["requesterTags"] = serde_json::json!([id]);
    profile["grants"] = Value::Array(
        definitions
            .iter()
            .map(|definition| {
                template["accessProfiles"]["standalone-service"]["grants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|grant| grant["definition"] == *definition)
                    .cloned()
                    .unwrap_or_else(|| {
                        let mut grant =
                            template["accessProfiles"]["standalone-service"]["grants"][0].clone();
                        grant["definition"] = serde_json::json!(definition);
                        grant
                    })
            })
            .collect(),
    );
    authority["accessProfiles"][id] = profile;
    fs::write(path, serde_norway::to_string(&authority).unwrap()).unwrap();
    evidencectl(project, &["access", "profile", "list"])
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("stdout utf8")
}

#[test]
fn unsafe_identifiers_and_unknown_definitions_change_nothing() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");

    let unsafe_id = declare_profile(project, "../escape", &["adult-status"]);
    assert!(!unsafe_id.status.success());
    assert!(!project.join("access").exists());

    write_project(project, "adult-status");
    let unknown = declare_profile(project, "missing-definition", &["not-authored"]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("AssertionDefinition"));
    assert!(!project.join("access").exists());
}

#[test]
fn access_profile_list_reports_the_shared_json_envelope() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fs::canonicalize(fixture.path()).expect("canonical project");
    let project = project.as_path();
    write_project(project, "adult-status");

    success(&declare_profile(project, "age-checks", &["adult-status"]));
    let profiles = json_output(&evidencectl(
        project,
        &["--format", "json", "access", "profile", "list"],
    ));
    assert_eq!(profiles["command"], "access profile list");
    assert_eq!(profiles["ok"], Value::Bool(true));
    assert_eq!(profiles["status"], "complete");
    assert_eq!(profiles["entries"][0]["id"], "age-checks");
    assert_eq!(
        profiles["entries"][0]["definitions"],
        serde_json::json!(["adult-status"])
    );
    assert!(profiles["entries"][0]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

fn json_output(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "JSON mode wrote human diagnostics: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid JSON report: {error}"))
}
