// SPDX-License-Identifier: Apache-2.0
//! The public check command checks root companions without entering runtime custody.
use serde_json::Value;
use std::{fs, path::Path, process::Command};

const WORKFLOW: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/workflow.yaml");
const FUNCTIONS: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/functions.rhai");
const RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml");
const SCENARIOS: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/scenarios.yaml");

fn project(path: &Path) {
    fs::write(path.join("workflow.yaml"), WORKFLOW).unwrap();
    fs::write(path.join("functions.rhai"), FUNCTIONS).unwrap();
}

fn check(path: &Path, extra: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args([
            "--format",
            "json",
            "check",
            "--project",
            path.to_str().unwrap(),
        ])
        .args(extra)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .env_remove("COORDINATOR_CHECK_PRODUCT")
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).expect("a JSON check report");
    (output.status.code().unwrap(), report)
}

#[test]
fn project_check_discovers_companions_and_aggregates_stray_yaml_refusals() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    project(&root);
    assert_eq!(check(&root, &[]).0, 0); // Both companions are optional.
    fs::write(
        root.join("runtime.yaml"),
        RUNTIME.replace("namespace: coordinator_demo", "namespace: null"),
    )
    .unwrap();
    fs::write(
        root.join("scenarios.yaml"),
        SCENARIOS.replace("type: success", "type: unsupported"),
    )
    .unwrap();
    fs::write(root.join("stray.yml"), "apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1\nkind: SchedulingProject\n").unwrap();
    let (exit, report) = check(&root, &[]);
    assert_eq!(exit, 1);
    let findings = report["diagnostics"].as_array().unwrap();
    for file in ["runtime.yaml", "scenarios.yaml", "stray.yml"] {
        assert!(
            findings.iter().any(|finding| finding["source"]["file"]
                .as_str()
                .is_some_and(|path| path.ends_with(file))),
            "{report}"
        );
    }
}

#[test]
fn project_check_executes_scenarios_and_checks_unused_step_references() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    project(&root);
    fs::write(root.join("scenarios.yaml"), SCENARIOS).unwrap();
    assert_eq!(check(&root, &[]).0, 0);
    let tested = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args([
            "--format",
            "json",
            "test",
            "--project",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(tested.status.success());
    let tested: Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(tested["diagnostics"], serde_json::json!([]));
    fs::write(
        root.join("scenarios.yaml"),
        SCENARIOS.replacen("state: completed", "state: refused", 1),
    )
    .unwrap();
    assert_eq!(check(&root, &[]).0, 1);
    fs::write(
        root.join("scenarios.yaml"),
        SCENARIOS.replacen(
            "replies:\n",
            "replies:\n    missing-step: [{type: success, value: null}]\n",
            1,
        ),
    )
    .unwrap();
    let (exit, report) = check(&root, &[]);
    assert_eq!(exit, 1);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "coordinator.scenarios.unknown-reference"),
        "{report}"
    );
    for (old, new, pointer) in [
        (
            "- read-application",
            "- missing-step",
            "/cases/0/expect/path/1",
        ),
        (
            "value: message-accepted",
            "value: missing-outcome",
            "/cases/0/expect/outcome/value",
        ),
    ] {
        fs::write(root.join("scenarios.yaml"), SCENARIOS.replacen(old, new, 1)).unwrap();
        let (exit, report) = check(&root, &[]);
        assert_eq!(exit, 1, "{report}");
        let findings = report["diagnostics"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{report}");
        assert_eq!(findings[0]["path"], pointer);
        assert!(findings[0]["source"]["line"].as_u64().is_some());
    }
}

#[test]
fn discovered_runtime_checks_bindings_and_substitutes_only_when_requested() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    project(&root);
    fs::write(
        root.join("runtime.yaml"),
        RUNTIME.replace("  notices:", "  other-notices:"),
    )
    .unwrap();
    let (exit, report) = check(&root, &[]);
    assert_eq!(exit, 1);
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["code"] == "coordinator.runtime.workflow-binding"));
    fs::write(
        root.join("runtime.yaml"),
        RUNTIME.replace(
            "namespace: coordinator_demo",
            "namespace: ${COORDINATOR_CHECK_PRODUCT}",
        ),
    )
    .unwrap();
    assert_eq!(check(&root, &[]).0, 0);
    // The environment flag reaches the discovered file too. No variable is
    // available in this controlled child, so substitution truthfully refuses.
    assert_eq!(check(&root, &["--environment"]).0, 1);
}

#[test]
fn relative_project_selection_resolves_discovered_runtime_files() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    project(&root);
    fs::write(root.join("runtime.yaml"), RUNTIME).unwrap();
    fs::write(root.join("scenarios.yaml"), SCENARIOS).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .current_dir(&root)
        .args(["--format", "json", "check", "--project", "./"])
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["diagnostics"], serde_json::json!([]));
}

#[test]
fn missing_appointment_task_authority_is_located_in_the_runtime_binding() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::write(
        root.join("workflow.yaml"),
        include_str!("../../../products/coordinator/examples/deferred-appointment/workflow.yaml"),
    )
    .unwrap();
    fs::write(
        root.join("functions.rhai"),
        include_str!("../../../products/coordinator/examples/deferred-appointment/functions.rhai"),
    )
    .unwrap();
    let mut runtime: Value = registry_coordinator::runtime::RuntimeConfig::loader()
        .parse_str::<Value>(
            include_str!(
                "../../../products/coordinator/examples/deferred-appointment/runtime.yaml"
            ),
            |_| None,
        )
        .unwrap()
        .config;
    runtime["connections"]["bookings"]["authorization"]
        .as_object_mut()
        .unwrap()
        .remove("taskAuthority");
    runtime["connections"]["bookings"]
        .as_object_mut()
        .unwrap()
        .remove("observationAuthorization");
    fs::write(
        root.join("runtime.yaml"),
        serde_norway::to_string(&runtime).unwrap(),
    )
    .unwrap();
    let (exit, report) = check(&root, &[]);
    assert_eq!(exit, 1);
    let finding = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["code"] == "coordinator.runtime.workflow-binding")
        .unwrap();
    assert_eq!(
        finding["path"],
        "/connections/bookings/authorization/taskAuthority"
    );
    assert!(finding["source"]["file"]
        .as_str()
        .unwrap()
        .ends_with("runtime.yaml"));
    assert!(finding["source"]["line"]
        .as_u64()
        .is_some_and(|line| line > 0));
}

#[test]
fn project_check_skips_custody_warns_for_children_and_deduplicates_explicit_runtime() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    project(&root);
    fs::create_dir(root.join(".coordinator")).unwrap();
    fs::write(
        root.join(".coordinator/runtime.yaml"),
        "PRIVATE-CUSTODY-CANARY",
    )
    .unwrap();
    assert_eq!(check(&root, &[]).0, 0);
    fs::create_dir(root.join("child")).unwrap();
    fs::write(root.join("child/stray.yaml"), "PRIVATE-CHILD-CANARY").unwrap();
    let (exit, report) = check(&root, &[]);
    assert_eq!(exit, 0);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.project.unread-directory"
    );
    assert_eq!(check(&root, &["--deny-warnings"]).0, 1);
    assert!(!report.to_string().contains("PRIVATE-"));
    fs::write(
        root.join("runtime.yaml"),
        RUNTIME.replace("product: breg", "product: ${COORDINATOR_CHECK_PRODUCT}"),
    )
    .unwrap();
    let runtime = root.join("runtime.yaml");
    let (exit, report) = check(&root, &["--runtime-config", runtime.to_str().unwrap()]);
    assert_eq!(exit, 0);
    assert_eq!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["path"] == "/connections/applications/product")
            .count(),
        1,
        "{report}"
    );
}

#[test]
fn project_check_refuses_misplaced_kinds_links_and_excess_entries() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    project(&root);
    fs::write(root.join("extra.yaml"), RUNTIME).unwrap();
    let (exit, report) = check(&root, &[]);
    assert_eq!(exit, 1);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.project.misplaced-kind"
    );
    fs::remove_file(root.join("extra.yaml")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("workflow.yaml"), root.join("extra.yaml")).unwrap();
        assert_eq!(
            check(&root, &[]).1["diagnostics"][0]["code"],
            "coordinator.project.not-a-regular-file"
        );
        fs::remove_file(root.join("extra.yaml")).unwrap();
    }
    for index in 0..1023 {
        fs::write(root.join(format!("entry-{index}")), "").unwrap();
    }
    assert_eq!(
        check(&root, &[]).1["diagnostics"][0]["code"],
        "coordinator.project.too-many-files"
    );
}
