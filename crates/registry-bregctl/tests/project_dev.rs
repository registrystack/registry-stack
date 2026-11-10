// SPDX-License-Identifier: Apache-2.0

use std::{fs, process::Command};

#[test]
fn a_malformed_plan_names_its_field_before_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fs::write(
        scratch.path().join("dev.yaml"),
        "apiVersion: id.registrystack.org/formats/project-dev/v1alpha1\nkind: ProjectDevPlan\nissuer: https://example.test\nproducts: [{product: coordinator, project: registry, audience: test}]\npeople: {}\njourney: {id: licensing, steps: []}\n",
    )
    .unwrap();
    let request = serde_json::json!({
        "action": "start", "project": scratch.path(), "json": true,
    });
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", &state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.dev.v1");
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("/products/0/product"),
        "{report}"
    );
    assert!(!state.exists());
}

#[test]
fn a_run_id_cannot_name_a_path() {
    let scratch = tempfile::tempdir().unwrap();
    let request = serde_json::json!({
        "action": "stop", "run_id": "../other-run", "json": true,
    });
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", scratch.path())
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["error"].as_str().unwrap().contains("run ID"));
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}
