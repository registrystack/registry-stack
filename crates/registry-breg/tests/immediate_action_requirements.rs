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
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["reason"] =
        json!("parent-inactive");
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
    source["actions"]["register-child"]["commitGuards"]["targets"][0] =
        json!({"input":"parent","revision":"unchanged","reason":"parent-inactive"});
    assert!(compile(source.clone())
        .unwrap_err()
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.action.guard-revision-invalid"));
    for invalid in ["Uppercase".to_owned(), "a".repeat(65), "has.dot".to_owned()] {
        source["actions"]["register-child"]["commitGuards"]["targets"][0]["reason"] =
            json!(invalid);
        assert!(parse_project_json(&serde_json::to_vec(&source).unwrap()).is_err());
    }
}

#[test]
fn a_guard_label_is_a_bounded_constant_that_requires_a_reason() {
    let guard = |members: Value| {
        let mut source = support::project();
        let target = &mut source["actions"]["register-child"]["commitGuards"]["targets"][0];
        for (key, value) in members.as_object().unwrap() {
            target[key] = value.clone();
        }
        source
    };
    let refused = |members: Value, code: &str| {
        let report = format!("{:?}", compile(guard(members)).unwrap_err());
        assert!(report.contains(code), "{report}");
    };

    let registry = compile(guard(json!({
        "reason": "parent-inactive", "label": "Only an active parent takes a child."
    })))
    .expect("a label beside its reason compiles");
    let compiled = &registry.actions().actions[0].requires[0];
    assert_eq!(compiled.reason.as_deref(), Some("parent-inactive"));
    assert_eq!(
        compiled.label.as_deref(),
        Some("Only an active parent takes a child.")
    );
    compile(guard(
        json!({"reason": "parent-inactive", "label": "é".repeat(128)}),
    ))
    .expect("256 bytes is the bound itself");

    refused(
        json!({"label": "A label without a reason."}),
        "breg.action.commit_guards.label-requires-reason",
    );
    for label in [
        "".to_owned(),
        "   ".to_owned(),
        "a".repeat(257),
        "é".repeat(129),
        "line\nbreak".to_owned(),
    ] {
        refused(
            json!({"reason": "parent-inactive", "label": label}),
            "breg.action.commit_guards.label-invalid",
        );
    }

    let unlabelled = compile(guard(json!({"reason": "parent-inactive"}))).unwrap();
    let compiled = serde_json::to_value(&unlabelled).unwrap();
    assert!(
        !compiled.to_string().contains("\"label\":\"Only"),
        "an Action without a label serializes without the member"
    );
}

#[test]
fn rewording_a_guard_label_changes_neither_the_action_revision_nor_the_migration_review_revision() {
    let guarded = |label: Option<&str>| {
        let mut source = support::project();
        let target = &mut source["actions"]["register-child"]["commitGuards"]["targets"][0];
        target["reason"] = json!("parent-inactive");
        if let Some(label) = label {
            target["label"] = json!(label);
        }
        compile(source).unwrap().actions().actions[0].clone()
    };
    let none = guarded(None);
    let first = guarded(Some("Only an active parent takes a child."));
    let second = guarded(Some("The parent must be active."));
    assert_ne!(first, second, "the compiled Actions differ by their label");
    assert_eq!(first.definition_revision, second.definition_revision);
    assert_eq!(first.definition_revision, none.definition_revision);
    assert_eq!(
        registry_breg::immediate_actions::migration_review_revision(&first),
        registry_breg::immediate_actions::migration_review_revision(&second)
    );
    assert_eq!(
        registry_breg::immediate_actions::migration_review_revision(&first),
        registry_breg::immediate_actions::migration_review_revision(&none)
    );
}

#[test]
fn action_requirements_can_compare_a_target_field_to_a_typed_action_input() {
    let mut source = support::project();
    source["actions"]["register-child"]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "expected-status", "type": "vocabulary-code", "vocabulary": "status",
            "values": ["active", "inactive"], "required": true, "classification": "restricted"
        }));
    source["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    let registry = compile(source).unwrap();
    let requirement = &registry.actions().actions[0].requires[0];
    assert_eq!(requirement.equals, None);
    assert_eq!(requirement.equals_input.as_deref(), Some("expected-status"));

    let mut wrong_type = support::project();
    wrong_type["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    wrong_type["actions"]["register-child"]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("label");
    let report = format!("{:?}", compile(wrong_type).unwrap_err());
    assert!(
        report.contains("breg.action.commit_guards.targets-value-invalid"),
        "{report}"
    );
}

#[test]
fn current_date_offsets_are_bounded_and_bound_to_current_date() {
    let mut source = ordered_guard_project();
    source["project"]["timezone"] = json!("UTC");
    source["actions"]["register-child"]["commitGuards"]["targets"] = json!([{
        "input": "parent", "field": "opened-on", "currentDate": "on-or-after",
        "currentDateOffsetDays": -30
    }]);
    let registry = compile(source.clone()).expect("a signed whole-day offset compiles");
    let guard = &registry.actions().actions[0].requires[0];
    assert_eq!(guard.current_date_offset_days, -30);

    source["actions"]["register-child"]["commitGuards"]["targets"][0]["currentDateOffsetDays"] =
        json!(0);
    let explicit_zero = compile(source.clone()).expect("zero keeps the existing comparison");
    source["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("currentDateOffsetDays");
    let absent = compile(source.clone()).expect("an absent offset keeps the existing comparison");
    assert_eq!(
        explicit_zero.actions().actions[0].requires[0],
        absent.actions().actions[0].requires[0]
    );

    source["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("currentDate");
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["currentDateOffsetDays"] =
        json!(1);
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.current-date-offset-invalid"));

    for offset in [-365_001, 365_001] {
        let mut source = ordered_guard_project();
        source["project"]["timezone"] = json!("UTC");
        source["actions"]["register-child"]["commitGuards"]["targets"] = json!([{
            "input": "parent", "field": "opened-on", "currentDate": "on-or-after",
            "currentDateOffsetDays": offset
        }]);
        assert!(format!("{:?}", compile(source).unwrap_err())
            .contains("breg.action.commit_guards.current-date-offset-invalid"));
    }
}

#[test]
fn current_date_month_offsets_are_bounded_bound_to_current_date_and_exclusive_with_days() {
    let guard_project = |members: Value| {
        let mut source = ordered_guard_project();
        source["project"]["timezone"] = json!("UTC");
        let mut guard = json!({"input": "parent", "field": "opened-on"});
        for (key, value) in members.as_object().unwrap() {
            guard[key] = value.clone();
        }
        source["actions"]["register-child"]["commitGuards"]["targets"] = json!([guard]);
        source
    };
    let refused = |members: Value| {
        let report = format!("{:?}", compile(guard_project(members)).unwrap_err());
        assert!(
            report.contains("breg.action.commit_guards.current-date-offset-invalid"),
            "{report}"
        );
    };

    let registry = compile(guard_project(
        json!({"currentDate": "on-or-after", "currentDateOffsetMonths": -3}),
    ))
    .expect("a signed whole-month offset compiles");
    let guard = &registry.actions().actions[0].requires[0];
    assert_eq!(guard.current_date_offset_months, -3);
    assert_eq!(guard.current_date_offset_days, 0);

    let explicit_zero = compile(guard_project(
        json!({"currentDate": "on-or-after", "currentDateOffsetMonths": 0}),
    ))
    .expect("zero keeps the existing comparison");
    let absent = compile(guard_project(json!({"currentDate": "on-or-after"})))
        .expect("an absent offset keeps the existing comparison");
    assert_eq!(
        explicit_zero.actions().actions[0].requires[0],
        absent.actions().actions[0].requires[0]
    );
    let compiled = serde_json::to_value(&absent).unwrap();
    assert!(
        !compiled.to_string().contains("currentDateOffsetMonths"),
        "a zero month offset leaves the compiled model, and every digest over it, unchanged"
    );

    for months in [12_000, -12_000] {
        compile(guard_project(
            json!({"currentDate": "on-or-after", "currentDateOffsetMonths": months}),
        ))
        .expect("the bound itself compiles");
    }
    for months in [12_001, -12_001] {
        refused(json!({"currentDate": "on-or-after", "currentDateOffsetMonths": months}));
    }
    refused(json!({"currentDateOffsetMonths": 1}));
    refused(json!({
        "currentDate": "on-or-after",
        "currentDateOffsetMonths": 1,
        "currentDateOffsetDays": 1
    }));
}

/// A project whose parent stores one ordered field of each kind and whose
/// action takes a required input of each kind.
fn ordered_guard_project() -> Value {
    let mut source = support::project();
    let fields = source["recordTypes"]["parent"]["fields"]
        .as_array_mut()
        .unwrap();
    for (id, kind) in [
        ("opened-on", "date"),
        ("opened-at", "timestamp"),
        ("quota", "int64"),
    ] {
        fields.push(json!({"id": id, "type": kind, "classification": "restricted"}));
    }
    let inputs = source["actions"]["register-child"]["inputs"]
        .as_array_mut()
        .unwrap();
    for (id, kind) in [("on", "date"), ("at", "timestamp"), ("limit", "int64")] {
        inputs.push(
            json!({"id": id, "type": kind, "required": true, "classification": "restricted"}),
        );
    }
    source["actions"]["register-child"]["commitGuards"]["targets"] = json!([]);
    source
}

fn ordered_guard(source: &mut Value, field: &str, key: &str, input: &str) {
    source["actions"]["register-child"]["commitGuards"]["targets"] =
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
        source["actions"]["register-child"]["inputs"][2]["required"] = json!(false);
        ordered_guard(&mut source, "opened-on", key, "on");
        assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));

        // One comparison per guard.
        let mut source = ordered_guard_project();
        ordered_guard(&mut source, "opened-on", key, "on");
        source["actions"]["register-child"]["commitGuards"]["targets"][0]["equalsFromInput"] =
            json!("on");
        assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));
        let mut source = ordered_guard_project();
        ordered_guard(&mut source, "opened-on", key, "on");
        source["actions"]["register-child"]["commitGuards"]["targets"][0]["atLeast"] = json!(1);
        assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));
    }
    let mut source = ordered_guard_project();
    ordered_guard(&mut source, "opened-on", "atLeastFromInput", "on");
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["atMostFromInput"] =
        json!("on");
    assert!(format!("{:?}", compile(source).unwrap_err()).contains(invalid));
}

#[test]
fn action_inputs_can_narrow_a_target_vocabulary_for_values_and_requirements() {
    let mut source = support::project();
    source["actions"]["register-child"]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "expected-status", "type": "vocabulary-code", "vocabulary": "status",
            "values": ["active"], "required": true, "classification": "restricted"
        }));
    source["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    compile(source).unwrap();

    let mut source = support::project();
    source["actions"]["register-child"]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "expected-status", "type": "vocabulary-code", "vocabulary": "other-status",
            "values": ["active"], "required": true, "classification": "restricted"
        }));
    source["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["equalsFromInput"] =
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
        source["actions"]["register-child"]["commitGuards"]["targets"][0][member] = value;
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
        let requirement = source["actions"]["register-child"]["commitGuards"]["targets"][0]
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
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["script"] = json!("true");
    assert!(parse_project_json(&serde_json::to_vec(&source).unwrap()).is_err());

    // An equality literal is a record value (CFG-EMPTY-1): the reader refuses
    // a mapping where it is written, without echoing it.
    let mut source = support::project();
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["equals"] =
        json!({"nested": "private-value-canary"});
    let failure = parse_project_yaml(&serde_json::to_vec(&source).unwrap()).unwrap_err();
    let [diagnostic] = failure.diagnostics() else {
        panic!("one refusal: {failure:?}");
    };
    assert_eq!(diagnostic.code, "config.invalid-type");
    assert_eq!(
        diagnostic.path,
        "project.actions.register-child.commitGuards.targets[0].equals"
    );
    assert!(!format!("{failure:?}").contains("canary"));
}

#[test]
fn action_requirements_keep_mandatory_scope_and_processing_boundaries() {
    let mut source = support::project();
    source["accessProfiles"]["registrar"]["requiredScopes"] = json!(["registry:register"]);
    assert!(
        compile(source).is_err(),
        "link grants do not waive target processing requirements"
    );
    let mut source = support::project();
    source["accessProfiles"]["registrar"]["permissions"]["actions"][0]["targets"] =
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
            0 => {
                source["actions"]["register-child"]["commitGuards"]["targets"][0]["equals"] =
                    json!("inactive")
            }
            1 => source["recordTypes"]["parent"]["fields"][0]["classification"] = json!("internal"),
            _ => source["actions"]["register-child"]["commitGuards"]["targets"] = json!([]),
        }
        assert_ne!(
            baseline,
            compile(source).unwrap().actions().actions[0].definition_revision
        );
    }
    let mut source = support::project();
    source["actions"]["register-child"]
        .as_object_mut()
        .unwrap()
        .remove("commitGuards");
    let no_requires = compile(source.clone()).unwrap();
    source["actions"]["register-child"]["commitGuards"]["targets"] = json!([]);
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
    let requirement = source["actions"]["register-child"]["commitGuards"]["targets"][0].clone();
    source["actions"]["register-child"]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(requirement);
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-duplicate"));
    let mut source = support::project();
    source["actions"]["register-child"]["inputs"][0]["required"] = json!(false);
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-reference-required"));
}

#[test]
fn action_requirements_do_not_bypass_reviewed_change_control() {
    let mut source = support::project();
    source["recordTypes"]["parent"]["mutationPolicy"] = json!({"patch":"proposal-required"});
    source["actions"]["register-child"]["inputs"].as_array_mut().unwrap().push(json!({
        "id": "status", "type": "vocabulary-code", "vocabulary": "status", "values": ["active", "inactive"], "required": true, "classification": "restricted"
    }));
    source["actions"]["register-child"]["plan"]["effects"].as_array_mut().unwrap().push(json!({
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
    source["actions"]["register-child"]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"expected-status", "type":"vocabulary-code", "vocabulary":"status",
            "values":["active","inactive"], "required":false, "classification":"restricted"
        }));
    source["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-value-invalid"));

    let mut source = support::project();
    source["recordTypes"]["parent"]["fields"][0]["required"] = json!(false);
    source["actions"]["register-child"]["commitGuards"]["targets"][0]["equals"] = Value::Null;
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
        "project.actions.register-child.commitGuards.targets[0].equals"
    );
    assert!(parse_project_json(&bytes).is_err());
    let requirement = source["actions"]["register-child"]["commitGuards"]["targets"][0]
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
    source["actions"]["register-child"]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("isNull");
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("breg.action.commit_guards.targets-value-invalid"));
}

/// `support::project()` plus `deactivate-parent`, an immediate Action that
/// patches an existing parent and guards the status the patch changes.
fn deactivate_project(execution: Value) -> Value {
    let mut source = support::project();
    source["actions"]["deactivate-parent"] = json!({
        "execution": execution,
        "inputs": [
            {"id": "parent", "apiName": "parentId", "type": "reference", "target": "parent", "required": true, "classification": "restricted"},
            {"id": "zone", "type": "string", "maximumLength": 32, "required": true, "classification": "restricted"}
        ],
        "commitGuards": {"targets": [
            {"input": "parent", "field": "status", "equals": "active", "reason": "not-active"}
        ]},
        "plan": {"type": "fixed", "effects": [
            {"id": "deactivate", "target": {"fromInput": "parent"}, "operation": "patch",
             "set": {"status": {"value": "inactive"}}}
        ]}
    });
    source["accessProfiles"]["registrar"]["permissions"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(json!({"action": "deactivate-parent", "operations": ["invoke"], "targets": [
            {"recordType": "parent", "rowBoundaries": [{"field": "zone", "claim": "zone", "operator": "equals"}]}
        ]}));
    source
}

fn current_revision() -> Value {
    json!({"mode": "immediate", "concurrency": "current-revision"})
}

fn deactivate_parent(
    registry: &registry_breg::CompiledRegistry,
) -> &registry_breg::model::CompiledAction {
    registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "deactivate-parent")
        .expect("the project declares deactivate-parent")
}

fn refused_with(source: Value, code: &str) -> String {
    let failure = compile(source).expect_err("the Action is refused");
    let report = format!("{failure:?}");
    assert!(
        failure.diagnostics().iter().any(|d| d.code == code),
        "expected {code}: {report}"
    );
    report
}

#[test]
fn a_current_revision_action_needs_no_condition_from_the_caller() {
    let conditioned = compile(deactivate_project(json!({"mode": "immediate"}))).unwrap();
    let before = deactivate_parent(&conditioned);
    assert!(before.condition_route.is_some());
    assert!(before
        .target_uses
        .iter()
        .any(|use_| use_.condition_required));

    let registry = compile(deactivate_project(current_revision())).unwrap();
    let action = deactivate_parent(&registry);
    assert!(action.condition_route.is_none());
    assert!(action
        .target_uses
        .iter()
        .all(|use_| !use_.condition_required));
    assert_eq!(
        action.concurrency,
        registry_breg::contract::ActionConcurrency::CurrentRevision
    );
    assert_ne!(
        action.definition_revision, before.definition_revision,
        "the concurrency mode is part of the Action's identity"
    );
    assert_ne!(
        registry_breg::immediate_actions::migration_review_revision(action),
        registry_breg::immediate_actions::migration_review_revision(before),
        "turning it on is a reviewed change"
    );
}

#[test]
fn omitting_concurrency_leaves_the_compiled_action_unchanged() {
    let omitted = compile(deactivate_project(json!({"mode": "immediate"}))).unwrap();
    let named = compile(deactivate_project(
        json!({"mode": "immediate", "concurrency": "condition-required"}),
    ))
    .unwrap();
    assert_eq!(
        serde_json::to_value(deactivate_parent(&omitted)).unwrap(),
        serde_json::to_value(deactivate_parent(&named)).unwrap()
    );
    assert!(!serde_json::to_string(deactivate_parent(&omitted))
        .unwrap()
        .contains("concurrency"));
}

#[test]
fn concurrency_is_refused_under_a_proposal_execution() {
    let mut source = deactivate_project(current_revision());
    let proposal = json!({"mode": "proposal", "concurrency": "current-revision"});
    source["actions"]["deactivate-parent"]["execution"] = proposal;
    let error = parse_project_json(&serde_json::to_vec(&source).unwrap())
        .expect_err("a proposal Action names no concurrency");
    assert!(format!("{error:?}").contains("concurrency"), "{error:?}");
}

#[test]
fn current_revision_refuses_a_revision_guard() {
    let mut source = deactivate_project(current_revision());
    source["actions"]["deactivate-parent"]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"input": "parent", "revision": "unchanged"}));
    refused_with(source, "breg.action.concurrency-revision-guard");
}

#[test]
fn current_revision_refuses_caller_values_written_into_an_existing_record() {
    let mut from_input = deactivate_project(current_revision());
    from_input["actions"]["deactivate-parent"]["plan"]["effects"][0]["set"] =
        json!({"status": {"value": "inactive"}, "zone": {"fromInput": "zone"}});
    let report = refused_with(from_input, "breg.action.concurrency-caller-value");
    assert!(
        report.contains("deactivate") && report.contains("zone"),
        "{report}"
    );

    let mut from_effect = deactivate_project(current_revision());
    from_effect["actions"]["deactivate-parent"] = json!({
        "execution": current_revision(),
        "inputs": [
            {"id": "child", "apiName": "childId", "type": "reference", "target": "child", "required": true, "classification": "restricted"}
        ],
        "commitGuards": {"targets": [{"input": "child", "field": "label", "equals": "old"}]},
        "plan": {"type": "fixed", "effects": [
            {"id": "fresh", "target": {"recordType": "parent"}, "operation": "create",
             "set": {"status": {"value": "active"}, "zone": {"value": "north"}}},
            {"id": "reparent", "target": {"fromInput": "child"}, "operation": "patch",
             "set": {"label": {"value": "new"}, "parent": {"fromEffect": "fresh"}}}
        ]}
    });
    from_effect["accessProfiles"]["registrar"]["permissions"]["actions"][1]["targets"] = json!([
        {"recordType": "parent", "rowBoundaries": "unrestricted"},
        {"recordType": "child", "rowBoundaries": "unrestricted"}
    ]);
    refused_with(from_effect, "breg.action.concurrency-caller-value");
}

#[test]
fn current_revision_allows_a_caller_value_into_a_created_record() {
    let mut source = deactivate_project(current_revision());
    source["actions"]["deactivate-parent"]["plan"]["effects"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id": "child", "target": {"recordType": "child"}, "operation": "create",
            "set": {"parent": {"fromInput": "parent"}, "label": {"fromInput": "zone"}}}),
        );
    source["accessProfiles"]["registrar"]["permissions"]["actions"][1]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"recordType": "child", "rowBoundaries": "unrestricted"}));
    compile(source).expect("a create takes a caller value under current-revision");
}

#[test]
fn current_revision_allows_clearing_a_field() {
    let mut source = support::project();
    source["recordTypes"]["parent"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "note", "type": "string", "maximumLength": 32, "classification": "restricted"}));
    let mut with_note = deactivate_project(current_revision());
    with_note["recordTypes"] = source["recordTypes"].clone();
    with_note["actions"]["deactivate-parent"]["plan"]["effects"][0]["clear"] = json!(["note"]);
    compile(with_note).expect("a clear is a constant");
}

#[test]
fn current_revision_needs_a_guard_the_write_falsifies() {
    // No guard on the patched record.
    let mut unguarded = deactivate_project(current_revision());
    unguarded["actions"]["deactivate-parent"]["commitGuards"] = json!({"targets": []});
    refused_with(unguarded, "breg.action.concurrency-guard-missing");

    // A guard on a field the write does not change.
    let mut elsewhere = deactivate_project(current_revision());
    elsewhere["actions"]["deactivate-parent"]["commitGuards"]["targets"] =
        json!([{"input": "parent", "field": "zone", "equals": "north"}]);
    refused_with(elsewhere, "breg.action.concurrency-guard-missing");

    // A guard the write leaves true: both want "inactive".
    let mut same = deactivate_project(current_revision());
    same["actions"]["deactivate-parent"]["commitGuards"]["targets"] =
        json!([{"input": "parent", "field": "status", "equals": "inactive"}]);
    refused_with(same, "breg.action.concurrency-guard-missing");

    // A guard that depends on the caller cannot be falsified by the write.
    let mut by_input = deactivate_project(current_revision());
    by_input["actions"]["deactivate-parent"]["commitGuards"]["targets"] =
        json!([{"input": "parent", "field": "zone", "equalsFromInput": "zone"}]);
    refused_with(by_input, "breg.action.concurrency-guard-missing");
}

#[test]
fn current_revision_accepts_a_null_guard_the_write_falsifies() {
    let mut source = support::project();
    source["recordTypes"]["parent"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "closed-on", "type": "string", "maximumLength": 32, "classification": "restricted"}));
    let mut open = deactivate_project(current_revision());
    open["recordTypes"] = source["recordTypes"].clone();
    open["actions"]["deactivate-parent"]["commitGuards"]["targets"] =
        json!([{"input": "parent", "field": "closed-on", "isNull": true}]);
    open["actions"]["deactivate-parent"]["plan"]["effects"][0]["set"] =
        json!({"closed-on": {"value": "2026-11-27"}});
    compile(open).expect("setting a field the guard requires unset falsifies the guard");
}
