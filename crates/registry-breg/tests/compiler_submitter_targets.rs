// SPDX-License-Identifier: Apache-2.0
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::model::CompiledQueryFilterOperator;
use serde_json::{json, Value};

fn source() -> Value {
    serde_norway::from_slice(include_bytes!(
        "../../../products/breg/starters/professional-licences/core/registry.yaml"
    ))
    .unwrap()
}

fn create_only_guard_source() -> Value {
    let mut candidate = source();
    candidate["entities"].as_array_mut().unwrap().push(json!({
        "id":"enrolment", "primaryDataset":"directory", "route":"enrolments",
        "mutationMode":"create_only", "classification":"restricted",
        "changeControl":{"requiredFor":["create"]},
        "fields":[{
            "id":"supporting-reference", "type":"string", "required":true,
            "classification":"restricted", "minLength":1, "maxLength":500
        }]
    }));
    candidate["entities"][1]["changeRequest"]["effects"] = json!([{
        "id":"create-enrolment", "target":{"entity":"enrolment"}, "operation":"create",
        "set":{"supporting-reference":{"fromField":"supporting-reference"}}
    }]);
    candidate["entities"][1]["changeRequest"]["application"] = json!({
        "preconditions":{"targets":[{
            "id":"licence-guard", "entity":"professional-license", "fromField":"record",
            "requires":[{"field":"person-reference", "equals":"person:holder"}]
        }]}
    });
    let reviewer = candidate["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "reviewer")
        .unwrap();
    reviewer["permissions"][1]["applyTargets"]
        .as_array_mut()
        .expect("reviewer apply targets")
        .push(json!({"entity":"enrolment", "rowBoundaries":[]}));
    candidate
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
            "missing-get" => holder["permissions"][0]["operations"] = json!(["list"]),
            "unknown-target" => holder["permissions"][1]["submitterTargets"] = json!(["unknown"]),
            "unreadable-reference" => {
                holder["permissions"][1]["readableFields"] = json!([
                    "licensed-activities",
                    "authorization-conditions",
                    "reason",
                    "supporting-reference"
                ])
            }
            "automatic" => {
                candidate["entities"][1]["changeRequest"]["onApproved"] =
                    json!({"mode":"automatic", "executor":"scope-correction-executor"})
            }
            "request-target" => {
                holder["permissions"][1]["submitterTargets"] = json!(["scope-correction"]);
                candidate["entities"][1]["fields"][0]["target"] = json!("scope-correction");
            }
            "optional-reference" => {
                candidate["entities"][1]["fields"][0]["required"] = json!(false)
            }
            "unwritable-reference" => {
                holder["permissions"][1]["writableFields"] = json!([
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

#[test]
fn create_only_requests_admit_exact_existing_application_guard_targets() {
    let candidate = create_only_guard_source();
    let project = parse_project_json(&serde_json::to_vec(&candidate).unwrap()).unwrap();
    let compiled = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let plan = compiled.entities()["scope-correction"]
        .change_request
        .as_ref()
        .unwrap();
    assert_eq!(
        plan.target_entities,
        ["enrolment".to_owned()].into_iter().collect()
    );
    assert_eq!(
        compiled.entities()["scope-correction"].access_profiles["holder"].submitter_targets,
        ["professional-license".to_owned()].into_iter().collect()
    );

    let mut widened = candidate;
    let holder = widened["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "holder")
        .unwrap();
    holder["permissions"][1]["submitterTargets"] = json!(["professional-license", "enrolment"]);
    let project = parse_project_json(&serde_json::to_vec(&widened).unwrap()).unwrap();
    let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.submitter_targets.invalid"));
}
