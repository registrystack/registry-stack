// SPDX-License-Identifier: Apache-2.0

use std::{fs, process::Command};

fn project(root: &std::path::Path, extra: &str) {
    fs::write(root.join("registry.yaml"), "fixture\n").unwrap();
    fs::write(
        root.join("dev.yaml"),
        format!(
            "# yaml-language-server: $schema=https://id.registrystack.org/schemas/breg/project-dev/project-dev.v1alpha1.schema.json\n\
apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\n\
kind: BRegProjectDev\n\
issuer: https://issuer.example.invalid\n\
products:\n  - {{product: breg, project: ., audience: registry}}\n\
people:\n  operator:\n    subject: operator\n    client: operator-client\n    grants:\n      breg: {{profile: operator, scopes: []}}\n\
journey:\n  id: smoke\n  steps:\n    - {{id: read, product: breg, as: operator, method: GET, path: /v1/records, expect: {{status: 200}}}}\n\
{extra}"
        ),
    )
    .unwrap();
}

fn check(root: &std::path::Path, state: &std::path::Path, json: bool) -> std::process::Output {
    let request = serde_json::json!({
        "action": "check", "project": root, "deny_warnings": true, "json": json,
    });
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap()
}

#[test]
fn check_validates_the_closed_plan_without_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "");

    let result = check(scratch.path(), &state, true);

    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["kind"], "BRegCtlReport");
    assert_eq!(report["command"], "dev-check");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["ok"], true);
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    assert!(!state.exists());
}

#[test]
fn check_refuses_an_unknown_plan_field_without_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "unexpected: true\n");

    let result = check(scratch.path(), &state, true);

    assert!(!result.status.success(), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(report["diagnostics"][0]["code"], "config.unknown-key");
    assert_eq!(report["diagnostics"][0]["path"], "/unexpected");
    assert!(!state.exists());
}

#[test]
fn check_renders_both_locations_of_a_duplicate_key() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "issuer: https://second.example.invalid\n");

    let result = check(scratch.path(), &state, false);

    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let human = String::from_utf8(result.stderr).unwrap();
    assert!(human.starts_with("error[yaml.duplicate-key] "), "{human}");
    assert!(human.contains("dev.yaml:17:1 /issuer"), "{human}");
    assert!(human.contains("dev.yaml:4:1 /issuer"), "{human}");
    assert!(
        human.contains("next: Keep one definition of the key."),
        "{human}"
    );
    assert!(!human.contains("second.example.invalid"));
    assert!(!state.exists());
}

#[test]
fn check_distinguishes_unavailable_input_from_an_invalid_plan() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "operational-failure");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "breg.project-dev.check-unavailable"
    );
    assert!(!state.exists());
}

#[test]
fn a_malformed_plan_names_its_field_before_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fs::write(
        scratch.path().join("dev.yaml"),
        "apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\nkind: BRegProjectDev\nissuer: https://example.test\nproducts: [{product: coordinator, project: registry, audience: test}]\npeople: {}\njourney: {id: licensing, steps: []}\n",
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
    assert!(report.get("diagnostics").is_none());
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
