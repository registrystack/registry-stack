// SPDX-License-Identifier: Apache-2.0
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::model::CompiledQueryFilterOperator;
use serde_json::{json, Value};

fn source() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../products/breg/starters/professional-licences/core/registry.yaml"
    ))
    .unwrap()
}

#[test]
fn native_reference_admission_requires_complete_manual_same_profile_authority() {
    let original = source();
    let project = parse_project_json(&serde_json::to_vec(&original).unwrap()).unwrap();
    let compiled = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let inventory = registry_breg::authority::authority_inventory(&compiled).unwrap();
    let person = &inventory.direct_claims["person_reference"];
    assert!(!person.multi_value);
    assert!(person.uses.iter().any(|use_| use_
        .surface
        .ends_with("submitterTargets/professional-license")));
    for case in [
        "missing-get",
        "unknown-target",
        "unreadable-reference",
        "automatic",
        "request-target",
        "optional-reference",
        "unwritable-reference",
    ] {
        let mut candidate = original.clone();
        let holder = candidate["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|profile| profile["id"] == "holder")
            .unwrap();
        match case {
            "missing-get" => holder["grants"][0]["operations"] = json!(["list"]),
            "unknown-target" => holder["grants"][1]["submitterTargets"] = json!(["unknown"]),
            "unreadable-reference" => {
                holder["grants"][1]["readableFields"] = json!([
                    "licensed-activities",
                    "authorization-conditions",
                    "reason",
                    "supporting-reference"
                ])
            }
            "automatic" => {
                candidate["entities"][1]["changeRequest"]["application"]["mode"] =
                    json!("automatic")
            }
            "request-target" => {
                holder["grants"][1]["submitterTargets"] = json!(["scope-correction"]);
                candidate["entities"][1]["fields"][0]["target"] = json!("scope-correction");
            }
            "optional-reference" => {
                candidate["entities"][1]["fields"][0]["required"] = json!(false)
            }
            "unwritable-reference" => {
                holder["grants"][1]["writableFields"] = json!([
                    "licensed-activities",
                    "authorization-conditions",
                    "reason",
                    "supporting-reference"
                ])
            }
            _ => unreachable!(),
        }
        let project = parse_project_json(&serde_json::to_vec(&candidate).unwrap()).unwrap();
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .err()
            .unwrap_or_else(|| panic!("{case} was accepted"));
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "change_request.submitter_targets.invalid"),
            "{case}: {failure:?}"
        );
    }
}

#[test]
fn professional_reviewer_can_filter_requests_by_readable_target_without_granting_editor_search() {
    let project = parse_project_json(&serde_json::to_vec(&source()).unwrap()).unwrap();
    let compiled = compile_project(&project, &[], CompileProfile::Authoring).unwrap();

    let reviewer = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.scope-correction.reviewer.list")
        .expect("reviewer correction list compiles");
    let record = reviewer
        .filter_fields
        .iter()
        .find(|field| field.field == "record")
        .expect("reviewer may filter by the already-readable target reference");
    assert!(record
        .operators
        .contains(&CompiledQueryFilterOperator::Equals));
    assert!(record.operators.contains(&CompiledQueryFilterOperator::In));

    let editor = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.scope-correction.editor.list")
        .expect("editor correction list compiles");
    assert!(
        editor
            .filter_fields
            .iter()
            .all(|field| field.field != "record"),
        "reading the target reference must not implicitly grant filtering"
    );
}
