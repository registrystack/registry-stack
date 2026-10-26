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
fn check_acceptance_reason_refuses_an_authored_expression() {
    let directory = tempfile::tempdir().expect("directory");
    let file = directory.path().join("check-acceptances.yaml");
    fs::write(
        &file,
        r#"apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1
kind: PlatformCheckAcceptances
acceptances:
  - code: evidence.project.duplicate-source-label
    scope: {file: evidence.yaml, path: /sources/person-record/label}
    reason: ${CHECK_ACCEPTANCE_REASON_CANARY}
"#,
    )
    .unwrap();

    let output = check_file(&file, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let report = json_report(&output);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "config.substitution-not-allowed"
    );
    assert_eq!(report["diagnostics"][0]["path"], "/acceptances/0/reason");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("CHECK_ACCEPTANCE_REASON_CANARY"));
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
    for (name, text, code) in [
        (
            "unknown-kind.json",
            r#"{"apiVersion": "id.registrystack.org/formats/other/v1", "kind": "Other"}"#,
            "config.wrong-kind",
        ),
        (
            "no-kind.json",
            r#"{"name": "something"}"#,
            "config.missing-envelope",
        ),
    ] {
        let file = directory.path().join(name);
        fs::write(&file, text).expect("write");

        let human = check_file(&file, &[]);
        assert_eq!(human.status.code(), Some(1), "{name}");
        let stderr = String::from_utf8_lossy(&human.stderr);
        assert!(stderr.contains(code), "{name}: {stderr}");
        assert!(
            stderr.contains("EvidenceSourceResolution"),
            "{name}: {stderr}"
        );

        let json = check_file(&file, &["--format", "json"]);
        assert_eq!(json.status.code(), Some(1), "{name}");
        let report = json_report(&json);
        assert_eq!(report["status"], "refused", "{name}");
        assert_eq!(report["diagnostics"][0]["code"], code, "{name}");
    }
}

/// A client file that still opens with the removed `schema` header is refused
/// by its own reader, which names the envelope to write.
#[test]
fn a_client_file_with_the_removed_schema_header_is_refused_naming_the_envelope() {
    let directory = tempfile::tempdir().expect("directory");
    for (relative, header, kind) in [
        (
            "evidence/examples/client-profile/client-profile.json",
            "registry.evidence-client-profile/v1",
            "EvidenceClientProfile",
        ),
        (
            "evidence/examples/client-contracts/evidence.contracts.json",
            "registry.evidence-client-contracts/v1",
            "EvidenceClientContracts",
        ),
    ] {
        let mut document: Value =
            serde_json::from_slice(&fs::read(example(relative)).expect("example")).expect("JSON");
        let members = document.as_object_mut().expect("an object");
        members.remove("apiVersion");
        members.remove("kind");
        members.insert("schema".to_owned(), Value::from(header));
        let file = directory.path().join(format!("{kind}.json"));
        fs::write(&file, serde_json::to_vec_pretty(&document).expect("JSON")).expect("write");

        let json = check_file(&file, &["--format", "json"]);
        assert_eq!(json.status.code(), Some(1), "{kind}");
        let report = json_report(&json);
        let removed = report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .find(|diagnostic| diagnostic["code"] == "config.removed-key")
            .unwrap_or_else(|| panic!("{kind}: no config.removed-key in {report}"));
        assert_eq!(removed["path"], "/schema", "{kind}");
        let action = removed["suggestedAction"].as_str().expect("an action");
        assert!(
            action.contains("apiVersion") && action.contains(kind),
            "{kind}: {action}"
        );
        assert!(
            !json
                .stdout
                .windows(header.len())
                .any(|window| window == header.as_bytes()),
            "{kind}: the report repeats the written header"
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

#[test]
fn check_help_says_the_project_is_required_unless_a_file_is_given() {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["check", "--help"])
        .output()
        .expect("run evidencectl");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("Required unless --file is given"),
        "check --help must say when PROJECT is required: {help}"
    );
}

#[test]
fn access_client_checks_share_native_content_rules_without_local_registration_state() {
    let source = example("evidence/examples/standalone/access/clients/example-caller.yaml");
    let directory = tempfile::tempdir().expect("directory");
    // The offline checker validates bytes even under a different filename.
    let file = directory.path().join("reviewed-client.yaml");
    let original = fs::read_to_string(&source).expect("access client example");
    fs::write(&file, &original).unwrap();
    let output = check_file(&file, &["--format", "json", "--deny-warnings"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(json_report(&output)["diagnostics"], serde_json::json!([]));

    for (text, path) in [
        (
            original.replace(
                "clientId: example-caller",
                "clientId: INVALID-PRIVATE-CANARY",
            ),
            "/clientId",
        ),
        (
            original.replace(
                "principal: urn:registrystack:evidence:local:client:example-caller",
                "principal: PRIVATE-CANARY",
            ),
            "/principal",
        ),
        (
            original.replace(
                "evidenceAudience: urn:example:audience:standalone-app",
                "evidenceAudience: PRIVATE-CANARY",
            ),
            "/evidenceAudience",
        ),
        (
            original.replace(
                "accessProfiles:\n  - standalone-service",
                "accessProfiles: []",
            ),
            "/accessProfiles",
        ),
        (
            original.replace(
                "keys:\n  - alg: ES256",
                "keys:\n  - d: PRIVATE-CANARY\n    alg: ES256",
            ),
            "/keys/0",
        ),
        (
            format!("{original}exchange:\n  kind: first-party\n  bootstrapScope: test\n"),
            "/exchange",
        ),
    ] {
        fs::write(&file, text).unwrap();
        let output = check_file(&file, &["--format", "json"]);
        assert_eq!(output.status.code(), Some(1), "{path}");
        let report = json_report(&output);
        assert_eq!(
            report["diagnostics"][0]["code"], "evidence.access.invalid-client",
            "{report}"
        );
        assert_eq!(report["diagnostics"][0]["path"], path);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-CANARY"));
    }
}

#[test]
fn access_client_offline_check_keeps_the_shared_document_byte_bound() {
    let original = fs::read_to_string(example(
        "evidence/examples/standalone/access/clients/example-caller.yaml",
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("client.yaml");
    let mut text = original;
    text.push('#');
    text.extend(std::iter::repeat_n('x', 1048575 - text.len()));
    text.push('\n');
    assert_eq!(text.len(), 1048576);
    fs::write(&file, &text).unwrap();
    assert_eq!(
        check_file(&file, &["--format", "json"]).status.code(),
        Some(0)
    );
    text.push('\n');
    fs::write(&file, text).unwrap();
    let output = check_file(&file, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let report = json_report(&output);
    assert_eq!(report["diagnostics"][0]["code"], "yaml.too-large");
    assert_eq!(report["diagnostics"][0]["path"], "");
    assert!(report["diagnostics"][0]["source"]["line"].is_null());
}
