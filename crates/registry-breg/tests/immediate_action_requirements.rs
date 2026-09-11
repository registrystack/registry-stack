// SPDX-License-Identifier: Apache-2.0

#[path = "support/action_requirements.rs"]
mod support;

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use serde_json::{json, Value};

fn compile(
    source: Value,
) -> Result<registry_breg::CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
}

#[test]
fn action_requirements_compile_processing_without_read_or_condition_grants() {
    let registry = compile(support::project()).unwrap();
    let action = &registry.actions().actions[0];
    assert!(action.condition_route.is_none());
    assert!(registry.routes().routes.is_empty());
    assert_eq!(action.requires.len(), 1);
    assert_eq!(action.requires[0].entity_id, "parent");
    assert_eq!(action.requires[0].field, "status");
    assert_eq!(action.requires[0].equals, Some(json!("active")));
    assert_eq!(action.requires[0].equals_input, None);
}

#[test]
fn action_requirements_can_compare_a_target_field_to_a_typed_action_input() {
    let mut source = support::project();
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "expected-status", "type": "vocabulary-code", "vocabulary": "status",
            "values": ["active", "inactive"], "required": true, "classification": "restricted"
        }));
    source["actions"][0]["requires"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["requires"][0]["equalsInput"] = json!("expected-status");
    let registry = compile(source).unwrap();
    let requirement = &registry.actions().actions[0].requires[0];
    assert_eq!(requirement.equals, None);
    assert_eq!(requirement.equals_input.as_deref(), Some("expected-status"));

    let mut wrong_type = support::project();
    wrong_type["actions"][0]["requires"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    wrong_type["actions"][0]["requires"][0]["equalsInput"] = json!("label");
    let report = format!("{:?}", compile(wrong_type).unwrap_err());
    assert!(report.contains("action.requires.value_invalid"), "{report}");
}

#[test]
fn action_inputs_can_narrow_a_target_vocabulary_for_values_and_requirements() {
    let mut source = support::project();
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "expected-status", "type": "vocabulary-code", "vocabulary": "status",
            "values": ["active"], "required": true, "classification": "restricted"
        }));
    source["actions"][0]["requires"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["requires"][0]["equalsInput"] = json!("expected-status");
    compile(source).unwrap();

    let mut source = support::project();
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "expected-status", "type": "vocabulary-code", "vocabulary": "other-status",
            "values": ["active"], "required": true, "classification": "restricted"
        }));
    source["actions"][0]["requires"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["requires"][0]["equalsInput"] = json!("expected-status");
    assert!(format!("{:?}", compile(source).unwrap_err()).contains("action.requires.value_invalid"));
}

#[test]
fn action_requirements_reject_unknown_fields_values_and_unbound_inputs() {
    for (member, value, expected) in [
        (
            "field",
            json!("unknown-field-canary"),
            "action.requires.field_unknown",
        ),
        (
            "equals",
            json!("unknown-value-canary"),
            "action.requires.value_invalid",
        ),
        (
            "equals",
            json!({"nested": "private-value-canary"}),
            "action.requires.value_invalid",
        ),
        ("equals", Value::Null, "action.requires.value_invalid"),
        (
            "input",
            json!("unknown-input-canary"),
            "action.requires.input_unknown",
        ),
        (
            "input",
            json!("label"),
            "action.requires.reference_required",
        ),
    ] {
        let mut source = support::project();
        source["actions"][0]["requires"][0][member] = value;
        let failure = compile(source).unwrap_err();
        let report = format!("{failure:?}");
        assert!(report.contains(expected), "{report}");
        assert!(
            !report.contains("canary"),
            "diagnostics must not echo source values"
        );
    }
    let mut source = support::project();
    source["actions"][0]["requires"][0]["script"] = json!("true");
    assert!(parse_project_json(&serde_json::to_vec(&source).unwrap()).is_err());
}

#[test]
fn action_requirements_keep_mandatory_scope_and_public_processing_boundaries() {
    let mut source = support::project();
    source["accessProfiles"][0]["requiredScopes"] = json!(["registry:register"]);
    assert!(
        compile(source).is_err(),
        "link grants do not waive target processing requirements"
    );
    let mut source = support::project();
    source["accessProfiles"][0]["anonymous"] = json!(true);
    source["accessProfiles"][0]["requiredScopes"] = json!([]);
    source["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("principalClaim");
    let report = format!("{:?}", compile(source).unwrap_err());
    assert!(
        report.contains("action.permission.anonymous_forbidden"),
        "{report}"
    );
    let mut source = support::project();
    source["accessProfiles"][0]["permissions"][0]["targets"] =
        json!([{"entity": "child", "rowBoundaries": []}]);
    assert!(
        compile(source).is_err(),
        "requirements cannot invent processing authority"
    );
}

#[test]
fn action_requirement_fingerprint_binds_predicate_and_related_field_contract() {
    let baseline = compile(support::project()).unwrap().actions().actions[0]
        .contract_fingerprint
        .clone();
    for mutate in [0, 1, 2] {
        let mut source = support::project();
        match mutate {
            0 => source["actions"][0]["requires"][0]["equals"] = json!("inactive"),
            1 => source["entities"][0]["fields"][0]["classification"] = json!("internal"),
            _ => source["actions"][0]["requires"] = json!([]),
        }
        assert_ne!(
            baseline,
            compile(source).unwrap().actions().actions[0].contract_fingerprint
        );
    }
    let mut source = support::project();
    source["actions"][0]
        .as_object_mut()
        .unwrap()
        .remove("requires");
    let no_requires = compile(source.clone()).unwrap();
    source["actions"][0]["requires"] = json!([]);
    let empty = compile(source).unwrap();
    assert_eq!(no_requires.actions(), empty.actions());
    assert!(serde_json::to_value(&empty.actions().actions[0])
        .unwrap()
        .get("requires")
        .is_none());
}

#[test]
fn action_requirements_reject_duplicate_and_optional_reference_checks() {
    let mut source = support::project();
    let requirement = source["actions"][0]["requires"][0].clone();
    source["actions"][0]["requires"]
        .as_array_mut()
        .unwrap()
        .push(requirement);
    assert!(format!("{:?}", compile(source).unwrap_err()).contains("action.requires.duplicate"));
    let mut source = support::project();
    source["actions"][0]["inputs"][0]["required"] = json!(false);
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("action.requires.reference_required"));
}

#[test]
fn action_requirements_do_not_bypass_reviewed_change_control() {
    let mut source = support::project();
    source["entities"][0]["changeControl"] = json!({"requiredFor": ["patch"]});
    source["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({
        "id": "status", "type": "vocabulary-code", "vocabulary": "status", "values": ["active", "inactive"], "required": true, "classification": "restricted"
    }));
    source["actions"][0]["effects"].as_array_mut().unwrap().push(json!({
        "id": "update-parent", "target": {"fromField": "parent"}, "operation": "patch", "set": {"status": {"fromField": "status"}}
    }));
    let failure = compile(source).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.effect.controlled_target"));
}
