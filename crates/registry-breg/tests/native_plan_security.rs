// SPDX-License-Identifier: Apache-2.0
//! Native named-function inputs, execution budgets, and failures stay closed.
use registry_breg::action_handler::{ActionHandlerError, ActionHandlerOutcome, evaluate_action};
use registry_breg::contract::ModuleAssetSource;
use registry_breg::{CompileProfile, compile_project_with_assets, parse_project_json};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn source() -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"native-plan-security","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://plans.example.test"},
        "datasets":[{"id":"test"}],
        "recordTypes":[{"id":"item","primaryDataset":"test","route":"items","mutationMode":"mutable",
            "fields":[{"id":"label","type":"string","maximumLength":64,"required":true,"classification":"internal"}]}],
        "functions":[{"id":"calculate","runtime":"rhai","source":"plans/calculate.rhai","entrypoint":"calculate","abi":"registry.action-plan/v1"}],
        "actions":[{"id":"register-item","execution":{"mode":"immediate"},
            "inputs":[{"id":"label","type":"string","maximumLength":64,"required":true,"classification":"internal"},
                {"id":"unbound","type":"string","maximumLength":64,"classification":"restricted"}],
            "plan":{"type":"function","function":"calculate","inputs":["label"],
                "writes":[{"id":"item","target":{"recordType":"item"},"operation":"create","fields":["label"]}]}}],
        "accessProfiles":[{"id":"registrar","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "permissions":{"actions":[{"action":"register-item","operations":["invoke"],"targets":[{"recordType":"item","rowBoundaries":"unrestricted"}],"results":["item"]}]}}]})
}
fn compile(script: &str) -> Result<registry_breg::CompiledRegistry, registry_breg::CompileFailure> {
    compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(&source()).unwrap())?,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/calculate.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
}
fn evaluate(script: &str, deadline: Instant) -> Result<ActionHandlerOutcome, ActionHandlerError> {
    let registry = compile(script).unwrap();
    evaluate_action(
        &registry.actions().actions[0],
        &serde_json::from_value(
            json!({"label":"synthetic-input-canary","unbound":"private-unbound-canary"}),
        )
        .unwrap(),
        deadline,
    )
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
const VALID: &str =
    "fn calculate(ctx) { #{effects:[#{id:\"item\",set:#{label:ctx.inputs.label}}]} }";
#[test]
fn named_function_inputs_and_ambient_capabilities_are_closed() {
    let script = "fn calculate(ctx) { if \"unbound\" in ctx.inputs { throw \"private-unbound-canary\"; } #{effects:[#{id:\"item\",set:#{label:ctx.inputs.label}}]} }";
    assert!(matches!(
        evaluate(script, deadline()).unwrap(),
        ActionHandlerOutcome::Effects(_)
    ));
    for script in [
        "import \"private\"; fn calculate(ctx) { #{} }",
        "fn calculate(ctx) { eval(\"1\"); }",
    ] {
        assert!(compile(script).is_err());
    }
    for expression in [
        "read_file(\"private\")",
        "getenv(\"private\")",
        "timestamp()",
        "random()",
        "ctx.claims",
        "ctx.records",
    ] {
        let script = format!("fn calculate(ctx) {{ {expression}; #{{effects:[]}} }}");
        assert!(evaluate(&script, deadline()).is_err(), "{expression}");
    }
}
#[test]
fn native_function_resource_and_deadline_refusals_leave_fresh_calls_healthy() {
    assert_eq!(
        evaluate("fn calculate(ctx) { loop {} }", deadline()).unwrap_err(),
        ActionHandlerError::Resource
    );
    assert_eq!(
        evaluate(VALID, Instant::now()).unwrap_err(),
        ActionHandlerError::Deadline
    );
    assert!(matches!(
        evaluate(VALID, deadline()).unwrap(),
        ActionHandlerOutcome::Effects(_)
    ));
}
#[test]
fn native_function_errors_do_not_render_source_or_input_values() {
    for script in [
        "fn calculate(ctx) { throw ctx.inputs.label; }",
        "fn calculate(ctx) { throw \"private-source-canary\"; }",
    ] {
        let error = evaluate(script, deadline()).unwrap_err();
        assert_eq!(error, ActionHandlerError::Execution);
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("canary"));
        assert!(matches!(
            evaluate(VALID, deadline()).unwrap(),
            ActionHandlerOutcome::Effects(_)
        ));
    }
}
