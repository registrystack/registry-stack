// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn project_check_acceptance_keeps_the_warning_and_allows_the_warning_gate() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().canonicalize().unwrap().join("bundle");
    let init = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .arg("init")
        .arg(&project)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    std::fs::write(project.join("notes.yaml"), "title: Project notes\n").unwrap();
    let check = || {
        Command::new(env!("CARGO_BIN_EXE_registry-render"))
            .args(["check", "--bundle"])
            .arg(&project)
            .args(["--format", "json", "--deny-warnings"])
            .output()
            .unwrap()
    };
    let before = check();
    assert_eq!(before.status.code(), Some(1));
    let before: serde_json::Value = serde_json::from_slice(&before.stdout).unwrap();
    assert_eq!(before["errors"], 0, "{before}");
    let files_before_acceptance = before["filesChecked"].as_u64().unwrap();
    let warning = before["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "render.bundle.unread-file")
        .unwrap();
    let input = serde_json::json!({
        "apiVersion": registry_platform_yaml::CHECK_ACCEPTANCES_API_VERSION,
        "kind": registry_platform_yaml::CHECK_ACCEPTANCES_KIND,
        "acceptances": [{"code":warning["code"], "scope":warning["scope"], "reason":"Project notes are intentionally kept beside the bundle."}]
    });
    std::fs::write(
        project.join("check-acceptances.yaml"),
        serde_json::to_vec(&input).unwrap(),
    )
    .unwrap();
    let after = check();
    assert!(
        after.status.success(),
        "{}",
        String::from_utf8_lossy(&after.stdout)
    );
    let after: serde_json::Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(
        after["filesChecked"],
        serde_json::json!(files_before_acceptance + 1)
    );
    assert_eq!(after["warnings"], 0);
    assert_eq!(after["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(after["diagnostics"][0]["severity"], "warning");
    assert_eq!(
        after["diagnostics"][0]["acceptedReason"],
        "Project notes are intentionally kept beside the bundle."
    );
}
