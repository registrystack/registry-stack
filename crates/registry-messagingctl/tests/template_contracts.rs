// SPDX-License-Identifier: Apache-2.0

//! Public CLI contract for deterministic Messaging template exports.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{json, Value};

fn messagingctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_messagingctl"))
        .args(arguments)
        .output()
        .expect("messagingctl runs")
}

fn success(arguments: &[&str]) -> Output {
    let output = messagingctl(arguments);
    assert!(
        output.status.success(),
        "messagingctl {arguments:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout is JSON")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("temporary path is UTF-8")
}

#[test]
fn generate_templates_exports_deterministic_checked_contracts_without_changing_the_package() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("project");
    success(&["init", path(&project)]);

    let before = json_stdout(&success(&[
        "--format=json",
        "package",
        path(&project),
        "--output",
        path(&temporary.path().join("unused-before")),
        "--dry-run",
    ]));

    let first = project.join("template-contracts.json");
    let first_report = json_stdout(&success(&[
        "--format=json",
        "generate",
        "templates",
        "--project",
        path(&project),
        "--output",
        path(&first),
    ]));
    assert_eq!(first_report["command"], "generate templates");
    assert_eq!(first_report["output"], path(&first));
    assert_eq!(first_report["templates"], 2);

    let second = temporary.path().join("template-contracts-second.json");
    success(&[
        "generate",
        "templates",
        "--project",
        path(&project),
        "--output",
        path(&second),
    ]);

    let first_bytes = std::fs::read(&first).unwrap();
    let second_bytes = std::fs::read(&second).unwrap();
    assert_eq!(first_bytes, second_bytes, "the export is byte-stable");
    assert_eq!(first_bytes.last(), Some(&b'\n'));

    let export: Value = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(
        export,
        json!({
            "apiVersion": "id.registrystack.org/formats/messaging/template-contracts/v1",
            "kind": "MessagingTemplateContracts",
            "templates": [
                {
                    "id": "appointment-reminder",
                    "version": "1",
                    "locales": ["en", "fr"],
                    "dataSchema": serde_json::from_slice::<Value>(
                        &std::fs::read(project.join(
                            "templates/appointment-reminder/1/schema.json"
                        )).unwrap()
                    ).unwrap(),
                },
                {
                    "id": "appointment-reminder-sms",
                    "version": "1",
                    "locales": ["en"],
                    "dataSchema": serde_json::from_slice::<Value>(
                        &std::fs::read(project.join(
                            "templates/appointment-reminder-sms/1/schema.json"
                        )).unwrap()
                    ).unwrap(),
                },
            ],
        })
    );

    let after = json_stdout(&success(&[
        "--format=json",
        "package",
        path(&project),
        "--output",
        path(&temporary.path().join("unused-after")),
        "--dry-run",
    ]));
    assert_eq!(before["projectDigest"], after["projectDigest"]);

    let installed = temporary.path().join("installed");
    success(&["package", path(&project), "--output", path(&installed)]);
    assert!(installed.join("SHA256SUMS").is_file());
    assert!(!installed.join("template-contracts.json").exists());
}

#[test]
fn generate_templates_is_create_only() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("project");
    success(&["init", path(&project)]);
    let output = temporary.path().join("contracts.json");
    std::fs::write(&output, b"keep this").unwrap();

    let refused = messagingctl(&[
        "--format=json",
        "generate",
        "templates",
        "--project",
        path(&project),
        "--output",
        path(&output),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    let report = json_stdout(&refused);
    assert_eq!(report["diagnostics"][0]["code"], "output.exists");
    assert_eq!(std::fs::read(&output).unwrap(), b"keep this");
}
