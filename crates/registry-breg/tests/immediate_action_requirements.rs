// SPDX-License-Identifier: Apache-2.0

#[path = "support/action_requirements.rs"]
mod support;

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, parse_project_yaml};
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
fn authored_guard_copy_keys_are_bounded_and_only_apply_to_field_guards() {
    let mut source = support::project();
    source["actions"][0]["commitGuards"]["targets"][0]["reason"] = json!("parent-inactive");
    assert_eq!(
        compile(source.clone()).unwrap().actions().actions[0].requires[0]
            .reason
            .as_deref(),
        Some("parent-inactive")
    );
    let mut direct = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    direct.actions[0].commit_guards.targets[0].reason =
        Some("private-invalid-reason-canary\n".into());
    let failure = compile_project(&direct, &[], CompileProfile::Authoring).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.identifier.invalid"
            && diagnostic.path.ends_with(".reason")));
    assert!(!format!("{failure:?}").contains("private-invalid-reason-canary"));
    source["actions"][0]["commitGuards"]["targets"][0] =
        json!({"input":"parent","revision":"unchanged","reason":"parent-inactive"});
    assert!(compile(source.clone())
        .unwrap_err()
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.action.guard-revision-invalid"));
    for invalid in ["Uppercase".to_owned(), "a".repeat(65), "has.dot".to_owned()] {
        source["actions"][0]["commitGuards"]["targets"][0]["reason"] = json!(invalid);
        assert!(parse_project_json(&serde_json::to_vec(&source).unwrap()).is_err());
    }
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
    source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    let registry = compile(source).unwrap();
    let requirement = &registry.actions().actions[0].requires[0];
    assert_eq!(requirement.equals, None);
    assert_eq!(requirement.equals_input.as_deref(), Some("expected-status"));

    let mut wrong_type = support::project();
    wrong_type["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    wrong_type["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] = json!("label");
    let report = format!("{:?}", compile(wrong_type).unwrap_err());
    assert!(
        report.contains("breg.action.commit_guards.targets-value-invalid"),
        "{report}"
    );
}

/// A project whose parent stores one ordered field of each kind and whose
/// action takes a required input of each kind.
fn ordered_guard_project() -> Value {
    let mut source = support::project();
    let fields = source["recordTypes"][0]["fields"].as_array_mut().unwrap();
    for (id, kind) in [
        ("opened-on", "date"),
        ("opened-at", "timestamp"),
        ("quota", "int64"),
    ] {
        fields.push(json!({"id": id, "type": kind, "classification": "restricted"}));
    }
    let inputs = source["actions"][0]["inputs"].as_array_mut().unwrap();
    for (id, kind) in [("on", "date"), ("at", "timestamp"), ("limit", "int64")] {
        inputs.push(
            json!({"id": id, "type": kind, "required": true, "classification": "restricted"}),
        );
    }
    source["actions"][0]["commitGuards"]["targets"] = json!([]);
    source
}

fn ordered_guard(source: &mut Value, field: &str, key: &str, input: &str) {
    source["actions"][0]["commitGuards"]["targets"] =
        json!([{"input": "parent", "field": field, key: input}]);
}

#[test]
fn action_requirements_can_order_a_target_field_against_a_typed_action_input() {
    for (field, input) in [("opened-on", "on"), ("opened-at", "at"), ("quota", "limit")] {
        let mut source = ordered_guard_project();
        ordered_guard(&mut source, field, "atMostFromInput", input);
        let registry = compile(source.clone()).unwrap();
        let requirement = &registry.actions().actions[0].requires[0];
        assert_eq!(requirement.field, field);
        assert_eq!(requirement.at_most_input.as_deref(), Some(input));
        assert_eq!(requirement.at_least_input, None);
        assert_eq!(requirement.equals, None);

        ordered_guard(&mut source, field, "atLeastFromInput", input);
        let registry = compile(source).unwrap();
        let requirement = &registry.actions().actions[0].requires[0];
        assert_eq!(requirement.at_least_input.as_deref(), Some(input));
        assert_eq!(requirement.at_most_input, None);
    }
}

#[test]
fn the_action_fingerprint_binds_the_direction_and_input_of_an_ordered_guard() {
    let revision = |field: &str, key: &str, input: &str| {
        let mut source = ordered_guard_project();
        ordered_guard(&mut source, field, key, input);
        compile(source).unwrap().actions().actions[0]
            .definition_revision
            .clone()
    };
    let at_most = revision("opened-on", "atMostFromInput", "on");
    assert_ne!(at_most, revision("opened-on", "atLeastFromInput", "on"));
    assert_ne!(at_most, revision("opened-at", "atMostFromInput", "at"));
    assert_eq!(at_most, revision("opened-on", "atMostFromInput", "on"));
}

#[test]
fn ordered_input_guards_refuse_mismatched_types_unordered_fields_and_unusable_inputs() {
    let invalid = "breg.action.commit_guards.targets-value-invalid";
    for key in ["atLeastFromInput", "atMostFromInput"] {
        for (field, input) in [
            // A date field against an instant input, and the reverse.
            ("opened-on", "at"),
            ("opened-at", "on"),
            // An integer field against a date input.
            ("quota", "on"),
            // A string field has no order, even against a string input.
            ("zone", "label"),
            // An undeclared input.
            ("opened-on", "undeclared-input-canary"),
        ] {
            let mut source = ordered_guard_project();
            ordered_guard(&mut source, field, key, input);
            let report = format!("{:?}", compile(source).unwrap_err());
            assert!(report.contains(invalid), "{field} {input}: {report}");
            assert!(
                !report.contains("canary"),
                "diagnostics must not echo source values"
            );
        }

        // An optional input may be absent, so a guard cannot rest on it.
        let mut source = ordered_guard_project();
        source["actions"][0]["inputs"][2]["required"] = json!(false);
        ordered_guard(&mut source, "opened-on", key, "on");
        assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));

        // One comparison per guard.
        let mut source = ordered_guard_project();
        ordered_guard(&mut source, "opened-on", key, "on");
        source["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] = json!("on");
        assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));
        let mut source = ordered_guard_project();
        ordered_guard(&mut source, "opened-on", key, "on");
        source["actions"][0]["commitGuards"]["targets"][0]["atLeast"] = json!(1);
        assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));
    }
    let mut source = ordered_guard_project();
    ordered_guard(&mut source, "opened-on", "atLeastFromInput", "on");
    source["actions"][0]["commitGuards"]["targets"][0]["atMostFromInput"] = json!("on");
    assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));
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
    source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    compile(source).unwrap();

    let mut source = support::project();
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "expected-status", "type": "vocabulary-code", "vocabulary": "other-status",
            "values": ["active"], "required": true, "classification": "restricted"
        }));
    source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-value-invalid"));
}

#[test]
fn action_requirements_reject_unknown_fields_values_and_unbound_inputs() {
    for (member, value, expected) in [
        (
            "field",
            json!("unknown-field-canary"),
            "breg.action.commit_guards.targets-field-unknown",
        ),
        (
            "equals",
            json!("unknown-value-canary"),
            "breg.action.commit_guards.targets-value-invalid",
        ),
        (
            "input",
            json!("unknown-input-canary"),
            "breg.action.commit_guards.targets-input-unknown",
        ),
        (
            "input",
            json!("label"),
            "breg.action.commit_guards.targets-reference-required",
        ),
    ] {
        let mut source = support::project();
        source["actions"][0]["commitGuards"]["targets"][0][member] = value;
        let failure = compile(source).unwrap_err();
        let report = format!("{failure:?}");
        assert!(report.contains(expected), "{report}");
        assert!(
            !report.contains("canary"),
            "diagnostics must not echo source values"
        );
    }
    // A required field is never unset, and `isNull` beside `equals` is two
    // comparisons.
    for keep_equals in [false, true] {
        let mut source = support::project();
        let requirement = source["actions"][0]["commitGuards"]["targets"][0]
            .as_object_mut()
            .unwrap();
        if !keep_equals {
            requirement.remove("equals");
        }
        requirement.insert("isNull".to_owned(), json!(true));
        assert!(format!("{:?}", compile(source).unwrap_err())
            .contains("breg.action.commit_guards.targets-value-invalid"));
    }
    let mut source = support::project();
    source["actions"][0]["commitGuards"]["targets"][0]["script"] = json!("true");
    assert!(parse_project_json(&serde_json::to_vec(&source).unwrap()).is_err());

    // An equality literal is a record value (CFG-EMPTY-1): the reader refuses
    // a mapping where it is written, without echoing it.
    let mut source = support::project();
    source["actions"][0]["commitGuards"]["targets"][0]["equals"] =
        json!({"nested": "private-value-canary"});
    let failure = parse_project_yaml(&serde_json::to_vec(&source).unwrap()).unwrap_err();
    let [diagnostic] = failure.diagnostics() else {
        panic!("one refusal: {failure:?}");
    };
    assert_eq!(diagnostic.code, "config.invalid-type");
    assert_eq!(
        diagnostic.path,
        "project.actions[0].commitGuards.targets[0].equals"
    );
    assert!(!format!("{failure:?}").contains("canary"));
}

#[test]
fn action_requirements_keep_mandatory_scope_and_processing_boundaries() {
    let mut source = support::project();
    source["accessProfiles"][0]["requiredScopes"] = json!(["registry:register"]);
    assert!(
        compile(source).is_err(),
        "link grants do not waive target processing requirements"
    );
    let mut source = support::project();
    source["accessProfiles"][0]["permissions"]["actions"][0]["targets"] =
        json!([{"recordType": "child", "rowBoundaries": "unrestricted"}]);
    assert!(
        compile(source).is_err(),
        "requirements cannot invent processing authority"
    );
}

#[test]
fn action_requirement_fingerprint_binds_predicate_and_related_field_contract() {
    let baseline = compile(support::project()).unwrap().actions().actions[0]
        .definition_revision
        .clone();
    for mutate in [0, 1, 2] {
        let mut source = support::project();
        match mutate {
            0 => source["actions"][0]["commitGuards"]["targets"][0]["equals"] = json!("inactive"),
            1 => source["recordTypes"][0]["fields"][0]["classification"] = json!("internal"),
            _ => source["actions"][0]["commitGuards"]["targets"] = json!([]),
        }
        assert_ne!(
            baseline,
            compile(source).unwrap().actions().actions[0].definition_revision
        );
    }
    let mut source = support::project();
    source["actions"][0]
        .as_object_mut()
        .unwrap()
        .remove("commitGuards");
    let no_requires = compile(source.clone()).unwrap();
    source["actions"][0]["commitGuards"]["targets"] = json!([]);
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
    let requirement = source["actions"][0]["commitGuards"]["targets"][0].clone();
    source["actions"][0]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(requirement);
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-duplicate"));
    let mut source = support::project();
    source["actions"][0]["inputs"][0]["required"] = json!(false);
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-reference-required"));
}

#[test]
fn action_requirements_do_not_bypass_reviewed_change_control() {
    let mut source = support::project();
    source["recordTypes"][0]["mutationPolicy"] = json!({"patch":"proposal-required"});
    source["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({
        "id": "status", "type": "vocabulary-code", "vocabulary": "status", "values": ["active", "inactive"], "required": true, "classification": "restricted"
    }));
    source["actions"][0]["plan"]["effects"].as_array_mut().unwrap().push(json!({
        "id": "update-parent", "target": {"fromInput": "parent"}, "operation": "patch", "set": {"status": {"fromInput": "status"}}
    }));
    let failure = compile(source).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.action.effect-controlled-target"));
}

#[test]
fn equality_inputs_must_be_required_and_an_unset_value_is_stated_explicitly() {
    let mut source = support::project();
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"expected-status", "type":"vocabulary-code", "vocabulary":"status",
            "values":["active","inactive"], "required":false, "classification":"restricted"
        }));
    source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-value-invalid"));

    let mut source = support::project();
    source["recordTypes"][0]["fields"][0]["required"] = json!(false);
    source["actions"][0]["commitGuards"]["targets"][0]["equals"] = Value::Null;
    // `null` is never a comparison literal (CFG-EMPTY-1): the reader refuses it
    // where it is written, and `isNull` states the unset value.
    let bytes = serde_json::to_vec(&source).unwrap();
    let failure = parse_project_yaml(&bytes).unwrap_err();
    let [diagnostic] = failure.diagnostics() else {
        panic!("one refusal: {failure:?}");
    };
    assert_eq!(diagnostic.code, "config.null-value");
    assert_eq!(
        diagnostic.path,
        "project.actions[0].commitGuards.targets[0].equals"
    );
    assert!(parse_project_json(&bytes).is_err());
    let requirement = source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap();
    requirement.remove("equals");
    requirement.insert("isNull".to_owned(), json!(true));
    let registry = compile(source.clone()).unwrap();
    assert_eq!(
        registry.actions().actions[0].requires[0].equals,
        Some(Value::Null)
    );
    let requirement = &registry.actions().actions[0].requires[0];
    let restored: registry_breg::model::CompiledCommitGuard =
        serde_json::from_value(serde_json::to_value(requirement).unwrap()).unwrap();
    assert_eq!(&restored, requirement);
    source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("isNull");
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-value-invalid"));
}
