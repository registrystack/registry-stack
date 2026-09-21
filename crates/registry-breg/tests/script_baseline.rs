// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use registry_breg::{
    action_handler::{
        compile_source, evaluate_action, evaluate_action_detailed, ActionHandlerError,
        ActionHandlerOutcome,
    },
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, parse_project_yaml, ModuleAssetSource},
    model::{CompiledAction, CompiledActionMutation, CompiledActionValue, CompiledChangeRequest},
    rhai_planner::{
        plan_change_request_effects, CandidateChangeRequestMutation, CandidateChangeRequestValue,
        ChangeRequestPlannerError, ChangeRequestPlannerRuntime,
    },
};
use serde_json::{json, Map, Value};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn action(script: &str) -> CompiledAction {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"script-baseline","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{"id":"record","primaryDataset":"baseline","route":"records","mutationMode":"mutable","fields":[
            {"id":"label","type":"string","maxLength":160,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"classification":"restricted"}
        ]}],
        "actions":[{"id":"register-record","inputs":[
            {"id":"label","apiName":"displayLabel","type":"string","maxLength":80,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","required":true,"classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"required":true,"classification":"restricted"},
            {"id":"note","type":"string","maxLength":80,"classification":"restricted"}
        ],"handler":{"kind":"rhai","script":"handlers/baseline.rhai","abi":"registry.action-handler/v1",
            "refusals":[{"code":"blank-label","label":"A label is required."}],
            "writes":[{"id":"record","target":{"entity":"record"},"operation":"create","fields":["label","count","amount"]}]
        }}],
        "accessProfiles":[{"id":"writer","default":true,"principalClaim":"principal","permissions":[
            {"action":"register-record","operations":["invoke"],"targets":[{"entity":"record","rowBoundaries":[]}],"results":["record"]}
        ]}]
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
            CompiledActionMutation::Set {
                field: name,
                value: CompiledActionValue::Literal { value },
            } if name == field => Some(value.clone()),
            _ => None,
        })
        .expect("expected literal field")
}

fn planner(script: &str) -> CompiledChangeRequest {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-name-change-rhai");
    let source = parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
    .entities()
    .get("person-name-change-request")
    .unwrap()
    .change_request
    .clone()
    .unwrap()
}

fn request() -> Map<String, Value> {
    json!({"person":"550e8400-e29b-41d4-a716-446655440000","given-name":" Mina ","family-name":"Rahman","handling":"routine"})
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn entrypoints_accept_named_parameters_and_private_helpers() {
    for (entrypoint, handler) in [("handle", true), ("plan", false)] {
        let script = format!(
            "private fn label(value) {{ value.trim(); value }} fn {entrypoint}(context) {{ label(` Alpha `) }}"
        );
        if handler {
            assert!(compile_source(&script).is_ok());
        } else {
            assert!(ChangeRequestPlannerRuntime::compile_source(&script).is_ok());
        }
    }
}

#[test]
fn entrypoint_errors_are_distinct_from_parse_errors() {
    for template in [
        "fn other(ctx) { #{} }",
        "fn ENTRY() { #{} }",
        "fn ENTRY(ctx, extra) { #{} }",
        "private fn ENTRY(ctx) { #{} }",
        "fn ENTRY(ctx) { #{} } fn helper(x) { x } fn helper(x, y) { x }",
    ] {
        assert_eq!(
            compile_source(&template.replace("ENTRY", "handle")).unwrap_err(),
            ActionHandlerError::Entrypoint
        );
        assert_eq!(
            ChangeRequestPlannerRuntime::compile_source(&template.replace("ENTRY", "plan"))
                .unwrap_err(),
            ChangeRequestPlannerError::Entrypoint
        );
    }
    assert_eq!(
        compile_source("fn handle(ctx) { let value = ; }").unwrap_err(),
        ActionHandlerError::Source
    );
    assert_eq!(
        ChangeRequestPlannerRuntime::compile_source("fn plan(ctx) { let value = ; }").unwrap_err(),
        ChangeRequestPlannerError::Source
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

#[test]
fn planner_supports_helpers_numeric_expressions_and_null_request_values() {
    let plan = planner(
        r#"private fn clean(value) { value.trim(); value }
        fn plan(ctx) {
            let label = clean(ctx.request["given-name"]);
            if ctx.request["family-name"] != () { label += " " + ctx.request["family-name"]; }
            label += " " + (7 / 2).to_string() + " " + (7.0 / 2.0).to_string();
            #{effects:[#{target:#{fromField:"person"},operation:"patch",set:#{"display-name":label}}]}
        }"#,
    );
    for (family_name, expected) in [
        (json!("Rahman"), "Mina Rahman 3 3.5"),
        (Value::Null, "Mina 3 3.5"),
    ] {
        let mut request = request();
        request.insert("family-name".into(), family_name);
        let candidate = plan_change_request_effects(&plan, &request, deadline()).unwrap();
        assert_eq!(candidate.effects.len(), 1);
        assert_eq!(candidate.effects[0].target.entity_id, "person");
        assert_eq!(
            candidate.effects[0].mutations,
            vec![CandidateChangeRequestMutation::Set {
                field: "display-name".into(),
                value: CandidateChangeRequestValue::Literal(json!(expected)),
            }]
        );
    }
}

#[test]
fn planner_runtime_errors_use_static_public_classification() {
    for (script, expected) in [
        (
            "fn plan(ctx) { throw ctx.request[\"given-name\"]; }",
            ChangeRequestPlannerError::Execution,
        ),
        ("fn plan(ctx) { 42 }", ChangeRequestPlannerError::Result),
    ] {
        let plan = planner(script);
        let mut request = request();
        request.insert("given-name".into(), json!("synthetic-private-label"));
        let error = plan_change_request_effects(&plan, &request, deadline()).unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(error.to_string(), error.code());
        assert!(ChangeRequestPlannerError::PLAN_REFUSALS.contains(&error));
        assert!(!error.problem_detail().contains("synthetic-private-label"));
        assert!(!error.problem_detail().contains(script));
    }
}
