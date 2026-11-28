// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn test_honours_the_declared_posture() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let ctl = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_schedulingctl"));
        command
            .args(["--format", "json"])
            .env_remove("REGISTRY_STACK_POSTURE");
        command
    };
    let initialized = ctl()
        .arg("init")
        .arg(&project)
        .args(["--template", "standalone-exact-time"])
        .output()
        .unwrap();
    assert!(initialized.status.success(), "{initialized:?}");
    let example = project.join("runtime.example.yaml");
    let document = std::fs::read_to_string(&example).unwrap();
    let document = document.replace(
        "database:\n",
        "database:\n  transport: private-network-plaintext\n",
    );
    std::fs::write(example, document).unwrap();
    let output = ctl().arg("test").arg(&project).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["path"] == "/database/transport"),
        "{report}"
    );
    let flagged = ctl()
        .arg("test")
        .arg(&project)
        .args(["--posture", "development"])
        .output()
        .unwrap();
    let from_env = ctl()
        .arg("test")
        .arg(&project)
        .env("REGISTRY_STACK_POSTURE", "development")
        .output()
        .unwrap();
    assert!(flagged.status.success(), "{flagged:?}");
    assert!(from_env.status.success(), "{from_env:?}");
}
