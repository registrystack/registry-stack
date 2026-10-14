// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use registry_breg::{
    action_handler::{
        compile_source, evaluate_action, evaluate_action_detailed, ActionHandlerError,
        ActionHandlerOutcome,
    },
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, ModuleAssetSource},
    model::{CompiledAction, CompiledPlanMutation, CompiledPlanValue},
};
use serde_json::{json, Map, Value};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn action(script: &str) -> CompiledAction {
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"script-baseline","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "datasets":[{"id":"baseline"}],
        "functions":[{"id":"baseline","runtime":"rhai","source":"handlers/baseline.rhai","entrypoint":"handle","abi":"registry.action-plan/v1"}],
        "recordTypes":[{"id":"record","primaryDataset":"baseline","route":"records","mutationMode":"mutable","fields":[
            {"id":"label","type":"string","maximumLength":160,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"classification":"restricted"}
        ]}],
        "actions":[{"id":"register-record","execution":{"mode":"immediate"},"inputs":[
            {"id":"label","apiName":"displayLabel","type":"string","maximumLength":80,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","required":true,"classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"required":true,"classification":"restricted"},
            {"id":"note","type":"string","maximumLength":80,"classification":"restricted"}
        ],"plan":{"type":"function","function":"baseline","inputs":["label","count","amount","note"],
            "refusals":[{"code":"blank-label","label":"A label is required."}],
            "writes":[{"id":"record","target":{"recordType":"record"},"operation":"create","fields":["label","count","amount"]}]
        }}],
        "accessProfiles":[{"id":"writer","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "actions":[
                {"action":"register-record","operations":["invoke"],"targets":[{"recordType":"record","rowBoundaries":"unrestricted"}],"results":["record"]}
            ]
        }}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "handlers/baseline.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
    .actions()
    .actions[0]
        .clone()
}

fn inputs() -> Map<String, Value> {
    json!({"label":" Alpha ","count":7,"amount":"123456789012345678.90"})
        .as_object()
        .unwrap()
        .clone()
}

fn handler_value(outcome: &ActionHandlerOutcome, field: &str) -> Value {
    let ActionHandlerOutcome::Effects(effects) = outcome else {
        panic!("expected effects")
    };
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].id, "record");
    effects[0]
        .mutations
        .iter()
        .find_map(|mutation| match mutation {
            CompiledPlanMutation::Set {
                field: name,
                value: CompiledPlanValue::Literal { value },
            } if name == field => Some(value.clone()),
            _ => None,
        })
        .expect("expected literal field")
}

#[test]
fn entrypoints_accept_named_parameters_and_private_helpers() {
    assert!(compile_source(
        "private fn label(value) { value.trim(); value } fn plan(context) { label(` Alpha `) }"
    )
    .is_ok());
}
#[test]
fn entrypoint_errors_are_distinct_from_parse_errors() {
    for script in [
        "fn other(ctx) { #{} }",
        "fn plan() { #{} }",
        "fn plan(ctx, extra) { #{} }",
        "private fn plan(ctx) { #{} }",
    ] {
        assert_eq!(
            compile_source(script).unwrap_err(),
            ActionHandlerError::Entrypoint
        );
    }
    assert_eq!(
        compile_source("fn plan(ctx) { let value = ; }").unwrap_err(),
        ActionHandlerError::Source
    );
}

#[test]
fn handler_supports_helpers_collections_conditionals_and_scalar_arithmetic() {
    let action = action(
        r#"private fn clean(value) { value.trim(); value }
        fn handle(ctx) {
            let parts = [clean(ctx.inputs.label), "record"];
            let label = "";
            for part in parts {
                if label != "" { label += "-"; }
                label += part;
            }
            #{effects:[#{id:"record",set:#{label:label,count:ctx.inputs.count / 2 + 1,amount:ctx.inputs.amount}}]}
        }"#,
    );
    let outcome = evaluate_action(&action, &inputs(), deadline()).unwrap();
    assert_eq!(handler_value(&outcome, "label"), json!("Alpha-record"));
    assert_eq!(handler_value(&outcome, "count"), json!(4));
    assert_eq!(
        handler_value(&outcome, "amount"),
        json!("123456789012345678.90")
    );
}

#[test]
fn handler_preserves_int64_values_and_decimal_strings() {
    let action = action(
        r#"fn handle(ctx) { #{effects:[#{id:"record",set:#{label:ctx.inputs.label,count:ctx.inputs.count,amount:ctx.inputs.amount}}]} }"#,
    );
    for count in [i64::MIN, -1, 0, i64::MAX] {
        let mut input = inputs();
        input.insert("count".into(), json!(count));
        let outcome = evaluate_action(&action, &input, deadline()).unwrap();
        assert_eq!(handler_value(&outcome, "count"), json!(count));
        assert_eq!(handler_value(&outcome, "amount"), input["amount"]);
    }
    for (field, value) in [("count", json!(7.5)), ("amount", json!(12.5))] {
        let mut input = inputs();
        input.insert(field.into(), value);
        assert_eq!(
            evaluate_action(&action, &input, deadline()).unwrap_err(),
            ActionHandlerError::Input
        );
    }
}

#[test]
fn handler_distinguishes_absence_null_and_present_optional_inputs() {
    let action = action(
        r#"fn handle(ctx) {
            let label = "absent";
            if "note" in ctx.inputs {
                label = if ctx.inputs.note == () { "null" } else { ctx.inputs.note };
            }
            #{effects:[#{id:"record",set:#{label:label}}]}
        }"#,
    );
    for (note, expected) in [
        (None, "absent"),
        (Some(Value::Null), "null"),
        (Some(json!("present")), "present"),
    ] {
        let mut input = inputs();
        if let Some(note) = note {
            input.insert("note".into(), note);
        }
        let outcome = evaluate_action(&action, &input, deadline()).unwrap();
        assert_eq!(handler_value(&outcome, "label"), json!(expected));
    }
}

#[test]
fn declared_handler_refusal_is_a_successful_business_outcome() {
    let action = action(r#"fn handle(ctx) { #{refusal:#{code:"blank-label",field:"label"}} }"#);
    let ActionHandlerOutcome::Refusal(refusal) =
        evaluate_action(&action, &inputs(), deadline()).unwrap()
    else {
        panic!("expected declared refusal")
    };
    assert_eq!(refusal.code, "blank-label");
    assert_eq!(refusal.label, "A label is required.");
    assert_eq!(refusal.field.as_deref(), Some("label"));
}

#[test]
fn handler_runtime_errors_use_static_public_classification() {
    for (script, expected) in [
        (
            "fn handle(ctx) { throw ctx.inputs.label; }",
            ActionHandlerError::Execution,
        ),
        ("fn handle(ctx) { 42 }", ActionHandlerError::Result),
        (
            r#"fn handle(ctx) { #{effects:[#{id:"record",set:#{label:()}}]} }"#,
            ActionHandlerError::Result,
        ),
    ] {
        let action = action(script);
        let mut input = inputs();
        input.insert("label".into(), json!("synthetic-private-label"));
        let error = evaluate_action_detailed(&action, &input, deadline()).unwrap_err();
        assert_eq!(error.kind, expected);
        assert_eq!(error.kind.to_string(), error.kind.code());
        for rendered in [format!("{error:?}"), error.kind.problem_detail().into()] {
            assert!(!rendered.contains("synthetic-private-label"));
            assert!(!rendered.contains(script));
        }
    }
}
