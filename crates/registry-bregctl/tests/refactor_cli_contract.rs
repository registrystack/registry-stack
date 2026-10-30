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
    root().join("products/breg/examples/facility")
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(args)
        .current_dir(root())
        .output()
        .unwrap()
}
fn explain_project(subject: &str, project: &Path) -> Value {
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
fn explain(subject: &str) -> Value {
    explain_project(subject, &fixture())
}
fn warning_fixture() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(
        temporary.path().join("registry.yaml"),
        r#"apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: warning-contract
  canonicalBaseIri: https://warning.example.test
  version: "1"
  defaultLanguage: en
package:
  sourceRevision: warning-contract-1
datasets:
  - id: directory
recordTypes:
  - id: entry
    route: entries
    primaryDataset: directory
    mutationMode: mutable
    classification: internal
    fields:
      - {id: code, type: string, required: true, maximumLength: 32, classification: internal}
      - {id: owner, type: string, required: true, maximumLength: 64, classification: internal}
accessProfiles:
  - id: reader
    default: true
    principalClaim: sub
    requiredScopes: ["entry:read"]
    permissions:
      records:
        - recordType: entry
          operations: [create, get, list]
          readableFields: [code, owner]
          writableFields: [code, owner]
          rowBoundaries:
            - {field: owner, claim: sub, operator: equals}
          allowDataExport: true
"#,
    )
    .unwrap();
    temporary
}
fn compiled() -> registry_breg::CompiledRegistry {
    let source = parse_project_yaml(include_bytes!(
        "../../../products/breg/examples/facility/registry.yaml"
    ))
    .unwrap();
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: include_bytes!(
                "../../../products/breg/examples/facility/plans/correct-address.rhai"
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
    let mut inspected_actions = inspection["actions"].clone();
    for action in inspected_actions.as_array_mut().unwrap() {
        // Display grouping belongs to the model explanation only.
        assert!(action.as_object_mut().unwrap().remove("grouping").is_some());
    }
    assert_eq!(actions["explanation"]["actions"], inspected_actions);
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

#[test]
fn explain_findings_share_checks_source_locations_and_json_pointers() {
    let fixture = warning_fixture();
    let project = fixture.path();
    let output = run(&["--format", "json", "check", project.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let checked: Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected = checked["diagnostics"].as_array().unwrap();
    assert_eq!(
        expected.len(),
        1,
        "the warning fixture has one review finding: {expected:?}"
    );
    assert_eq!(expected[0]["code"], "breg.access.profile-data-export");
    for subject in [
        "model",
        "access",
        "routes",
        "queries",
        "actions",
        "proposals",
        "events",
    ] {
        let report = explain_project(subject, project);
        assert_eq!(report["diagnostics"], checked["diagnostics"], "{subject}");
        for finding in report["diagnostics"].as_array().unwrap() {
            assert!(finding["path"].as_str().unwrap().starts_with('/'));
            assert!(finding["source"]["file"]
                .as_str()
                .unwrap()
                .ends_with("registry.yaml"));
            assert!(finding["source"]["line"].as_u64().unwrap() > 0);
            assert!(finding["source"]["column"].as_u64().unwrap() > 0);
            assert_eq!(finding["severity"], "warning");
        }
    }
}

fn assert_service_routes_match_openapi(project: &Path, registry: &registry_breg::CompiledRegistry) {
    let output = run(&[
        "--format",
        "json",
        "explain",
        "routes",
        project.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let mut expected = std::collections::BTreeMap::new();
    for (path, item) in openapi["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let Some(id) = operation["operationId"].as_str() else {
                continue;
            };
            if id.starts_with("proposals.") || id.starts_with("statistics.") {
                expected.insert(id.to_owned(), (method.to_uppercase(), path.clone()));
            }
        }
    }
    assert!(!expected.is_empty());
    let mut actual = std::collections::BTreeMap::new();
    for route in report["explanation"]["routes"].as_array().unwrap() {
        if matches!(route["type"].as_str(), Some("proposal" | "statistics")) {
            let path = route["path"].as_str().unwrap();
            let method = route["method"].as_str().unwrap();
            let operation = &openapi["paths"][path][method.to_lowercase()];
            assert_eq!(
                route["accessProfiles"],
                operation["x-registry-accessProfiles"]
            );
            for (header, member) in [
                ("Idempotency-Key", "requiresIdempotencyKey"),
                ("If-Match", "requiresIfMatch"),
            ] {
                let required =
                    operation["parameters"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|parameter| {
                            parameter["in"] == "header"
                                && parameter["name"] == header
                                && parameter["required"] == true
                        });
                assert_eq!(route[member], required, "{route}");
            }
            assert!(actual
                .insert(
                    route["id"].as_str().unwrap().to_owned(),
                    (method.to_owned(), path.to_owned())
                )
                .is_none());
        }
        if route["type"] == "action" && route["actionRouteKind"] == "start" {
            assert_eq!(route["requiresIdempotencyKey"], true);
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn proposal_instance_route_inspection_matches_generated_client_contract() {
    assert_service_routes_match_openapi(&fixture(), &compiled());
}

#[test]
fn statistical_route_inspection_matches_generated_client_contract() {
    let mut source = registry_platform_yaml::Reader::new("registry.yaml")
        .scan(include_bytes!(
            "../../../products/breg/examples/minimal/registry.yaml"
        ))
        .unwrap()
        .unwrap()
        .to_json_value();
    // The added required fields are outside the canonical Actions' plans.
    source.as_object_mut().unwrap().remove("actions");
    let editor = source["accessProfiles"][0]["permissions"]
        .as_object_mut()
        .unwrap();
    editor.remove("actions");
    editor.remove("proposals");
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"id":"active","type":"boolean","required":true,"classification":"internal"}),
            json!({"id":"event-date","type":"date","required":true,"classification":"internal"}),
        ]);
    source["accessProfiles"].as_array_mut().unwrap().push(json!({
        "id":"analyst","principalClaim":"principal","requiredScopes":["statistics:read"],
        "permissions":{
            "records":[{"recordType":"contact","operations":["list"],"readableFields":["active","event-date"],
                "filterableFields":["active","event-date"],"rowBoundaries":"unrestricted","allowCount":true}],
            "datasets":[{"dataset":"contacts-by-active","operations":["read-live"]}]
        }
    }));
    source["project"]["timezone"] = json!("UTC");
    source["statisticalDatasets"] = json!([{
        "id":"contacts-by-active","unit":"contact","population":"active eq true",
        "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
        "dimensions":["active"],"disclosure":{"minimumCount":5,"roundingBase":5}
    }]);
    let bytes = serde_norway::to_string(&source).unwrap();
    let authored = parse_project_yaml(bytes.as_bytes()).unwrap();
    let registry =
        registry_breg::compiler::compile_project(&authored, &[], CompileProfile::Authoring)
            .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("registry.yaml"), bytes).unwrap();
    assert_service_routes_match_openapi(temporary.path(), &registry);
}

#[test]
fn human_inspection_summarizes_governed_behavior_without_dumping_documents() {
    let project = fixture();
    for (subject, expected) in [
        ("model", "proposal-required"),
        ("access", "facility-correction-author"),
        ("actions", "write ceiling: patch facility"),
        ("proposals", "plans/correct-address.rhai"),
        ("routes", "/v1/proposals/"),
        ("queries", "readable fields"),
        ("events", "No event deliveries declared."),
        ("lifecycle", "submit: draft -> submitted"),
    ] {
        let mut args = vec!["explain", subject];
        if subject != "lifecycle" {
            args.push(project.to_str().unwrap());
        }
        let output = run(&args);
        assert!(output.status.success(), "{subject}: {output:?}");
        let human = String::from_utf8(output.stdout).unwrap();
        assert!(human.contains(expected), "{subject}: {human}");
        if matches!(subject, "actions" | "access") {
            assert!(
                human.contains("commit guard operator.jurisdiction: equals input jurisdiction"),
                "{subject}: {human}"
            );
        }
        assert!(
            !human.contains("\"apiVersion\":"),
            "raw JSON document in {subject}"
        );
        assert!(!human.contains("\"scriptBytes\":"));
        assert!(!human.contains("\"sqlBytes\":"));
    }
}

#[test]
fn proposal_start_route_kind_and_required_key_match_its_operation() {
    let value = explain("routes");
    let starts = value["explanation"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|route| route["type"] == "action" && route["operation"] == "start")
        .collect::<Vec<_>>();
    assert_eq!(starts.len(), 2);
    for route in starts {
        assert_eq!(route["actionRouteKind"], "start");
        assert_eq!(route["requiresIdempotencyKey"], true);
    }
}
