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
    let relationships = model["explanation"]["recordTypes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|record_type| record_type["relationships"].as_object().unwrap().values())
        .collect::<Vec<_>>();
    assert!(!relationships.is_empty());
    for relationship in relationships {
        assert!(relationship["sourceRecordType"].is_string());
        assert!(relationship["targetRecordType"].is_string());
        assert!(relationship.get("sourceEntityId").is_none());
        assert!(relationship.get("targetEntityId").is_none());
    }
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
        let explanation = &document["explanation"];
        assert!(explanation.is_object());
        match subject {
            "access" => {
                assert!(explanation["recordTypes"].is_array());
                assert!(explanation.get("entities").is_none());
                for entry in explanation["routes"]["entries"].as_array().unwrap() {
                    assert!(entry["recordType"].is_string());
                    assert!(entry.get("entityId").is_none());
                }
            }
            "routes" => {
                let routes = explanation["routes"].as_array().unwrap();
                assert!(routes.iter().any(|route| route["type"] == "record"));
                for route in routes.iter().filter(|route| route["type"] == "record") {
                    assert!(route["recordType"].is_string());
                    assert!(route.get("entityId").is_none());
                }
            }
            "queries" => {
                let operations = explanation["operations"].as_array().unwrap();
                assert!(!operations.is_empty());
                for operation in operations {
                    assert!(operation["recordType"].is_string());
                    assert!(operation.get("entity").is_none());
                }
            }
            "events" => {}
            _ => unreachable!(),
        }
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
    for arguments in [
        vec!["data", "validate", "--help"],
        vec!["data", "import", "--help"],
        vec!["data", "export", "--help"],
        vec!["generate", "--help"],
        vec!["import-authority", "open", "--help"],
        vec!["dev", "prepare-source", "--help"],
    ] {
        let output = run(&arguments);
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--record-type"), "{help}");
        assert!(!help.contains("--entity"), "{help}");
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

#[test]
fn record_schema_and_openapi_use_breg_terms_without_respelling_registry_record_v1() {
    let registry = compiled();
    let schema: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/schemas/directory-entry.schema.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(schema["$id"], "urn:breg:record-type:directory-entry");
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let operation = &openapi["paths"]["/v1/records/directory-entries/{record_id}"]["get"];
    assert_eq!(operation["x-registry-recordType"], "directory-entry");
    assert_eq!(
        operation["x-registry-responseRecordType"],
        "directory-entry"
    );
    assert!(operation.get("x-registry-entity").is_none());
    assert!(operation.get("x-registry-responseEntity").is_none());
    let metadata = &operation["responses"]["200"]["content"]["application/json"]["schema"]
        ["properties"]["meta"]["properties"];
    assert_eq!(metadata["entityTypeIdentifier"]["const"], "directory-entry");
    assert!(metadata.get("recordType").is_none());
    let problem = &openapi["components"]["schemas"]["Problem"]["properties"];
    assert!(problem["recordType"].is_object());
    assert!(problem.get("entityId").is_none());
}
