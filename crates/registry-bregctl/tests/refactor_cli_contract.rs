// SPDX-License-Identifier: Apache-2.0
//! Execute the canonical CLI contract and compare it with the compiled inspector.
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_yaml, ModuleAssetSource};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
fn fixture() -> PathBuf {
    root().join("products/breg/examples/refactor/facility")
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(args)
        .current_dir(root())
        .output()
        .unwrap()
}
fn explain(subject: &str) -> Value {
    let project = fixture();
    let mut arguments = vec!["--format", "json", "explain", subject];
    if subject != "lifecycle" {
        arguments.push(project.to_str().unwrap());
    }
    let output = run(&arguments);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["ok"], true);
    assert_eq!(document["kind"], "BRegCtlReport");
    document
}
fn compiled() -> registry_breg::CompiledRegistry {
    let source = parse_project_yaml(include_bytes!(
        "../../../products/breg/examples/refactor/facility/registry.yaml"
    ))
    .unwrap();
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: include_bytes!(
                "../../../products/breg/examples/refactor/facility/plans/correct-address.rhai"
            )
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
}
#[test]
fn model_and_actions_share_the_compiled_definition_inspector() {
    let registry = compiled();
    let model = explain("model");
    let inspection = registry_breg::artifacts::inspect_registry(&registry);
    assert_eq!(
        model["explanation"]["recordTypes"],
        inspection["recordTypes"]
    );
    assert!(model["explanation"].get("entities").is_none());
    let actions = explain("actions");
    assert_eq!(actions["explanation"]["actions"], inspection["actions"]);
    assert!(actions["revision"].as_str().unwrap().starts_with("sha256:"));
    for action in actions["explanation"]["actions"].as_array().unwrap() {
        assert!(action["revision"].as_str().unwrap().starts_with("sha256:"));
        assert!(action.get("contractFingerprint").is_none());
        assert!(action["apiName"].is_string());
        assert!(action["display"].is_object());
        assert!(matches!(
            action["execution"]["mode"].as_str(),
            Some("immediate" | "proposal")
        ));
    }
}
#[test]
fn proposals_are_the_fixed_proposal_actions_without_record_request_resources() {
    let document = explain("proposals");
    assert_eq!(document["explanation"]["kind"], "BRegProposalsExplanation");
    let actions = document["explanation"]["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 2);
    assert!(actions
        .iter()
        .all(|action| action["execution"]["mode"] == "proposal"));
    assert!(actions
        .iter()
        .any(|action| action["id"] == "correct-address"));
    assert!(actions
        .iter()
        .any(|action| action["id"] == "deactivate-facility"));
    let retired = run(&["explain", "change-requests", fixture().to_str().unwrap()]);
    assert!(!retired.status.success());
}
#[test]
fn lifecycle_catalogue_matches_the_engine_without_compiling_a_project() {
    let document = explain("lifecycle");
    assert!(document.get("revision").is_none());
    let value = serde_json::to_value(registry_breg::lifecycle::proposal_lifecycle()).unwrap();
    assert_eq!(document["explanation"]["lifecycles"][0], value);
    let source = serde_json::to_string(&value).unwrap();
    for operation in [
        "edit", "rebase", "retry", "submit", "apply", "cancel", "revise",
    ] {
        assert!(source.contains(operation));
    }
    for args in [
        vec!["explain", "lifecycle", fixture().to_str().unwrap()],
        vec!["explain", "lifecycle", "--production"],
    ] {
        assert!(!run(&args).status.success());
    }
}
#[test]
fn ordinary_access_route_query_and_event_catalogues_remain_executable() {
    for subject in ["access", "routes", "queries", "events"] {
        let document = explain(subject);
        assert!(document["explanation"].is_object());
        assert!(document["revision"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }
}
#[test]
fn cli_catalogue_exposes_only_current_action_and_proposal_commands() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("proposal-retention"));
    assert!(!help.contains("request-retention"));
    let output = run(&["project", "--help"]);
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("action-test"));
    assert!(!help.contains("planner-test"));
    assert!(!run(&["explain", "actions"]).status.success());
    for operation in ["validate", "import", "export"] {
        let output = run(&["data", operation, "--help"]);
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--record-type"));
        assert!(!help.contains("--entity"));
    }
}
#[test]
fn generated_proposal_paths_have_no_target_condition_operation() {
    let registry = compiled();
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(openapi["paths"]["/v1/proposals"]["get"].is_object());
    assert!(openapi["paths"]["/v1/proposals/{proposal_id}/apply"]["post"].is_object());
    assert_eq!(
        openapi["paths"]["/v1/proposals/{proposal_id}/apply"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["required"],
        json!(["submissionVersion", "effectDigest"])
    );
    let paths = openapi["paths"].as_object().unwrap();
    assert!(!paths
        .keys()
        .any(|path| path.contains("correct-address") && path.contains("condition")));
}
