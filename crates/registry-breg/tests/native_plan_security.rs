// SPDX-License-Identifier: Apache-2.0
//! Native named-function inputs, execution budgets, and failures stay closed.
use registry_breg::action_handler::{evaluate_action, ActionHandlerError, ActionHandlerOutcome};
use registry_breg::contract::ModuleAssetSource;
use registry_breg::model::{CompiledPlanMutation, CompiledPlanValue};
use registry_breg::{compile_project_with_assets, parse_project_json, CompileProfile};
use serde_json::{json, Value};
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
/// Evaluate a compiled `script` on its own thread under a deadline `budget`
/// after compilation. A call that has not returned within a second fails the
/// case instead of hanging the suite.
fn evaluate_within(
    script: &str,
    budget: Duration,
) -> Result<ActionHandlerOutcome, ActionHandlerError> {
    let registry = compile(script).unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let started = Instant::now();
    std::thread::spawn(move || {
        let outcome = evaluate_action(
            &registry.actions().actions[0],
            &serde_json::from_value(json!({"label":"synthetic-input-canary"})).unwrap(),
            Instant::now() + budget,
        );
        sender
            .send(outcome)
            .expect("the watchdog is still waiting for this plan");
    });
    receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|_| {
            panic!(
                "the plan held its thread for {:?} under a {budget:?} deadline: {script}",
                started.elapsed()
            )
        })
}
const VALID: &str =
    "fn calculate(ctx) { #{effects:[#{id:\"item\",set:#{label:ctx.inputs.label}}]} }";
/// The valid plan with `statement` run first, so only the statement can
/// refuse it.
fn valid_after(statement: &str) -> String {
    VALID.replacen("(ctx) { ", &format!("(ctx) {{ {statement}; "), 1)
}
/// A call named in the source to a function the plan engine leaves out is
/// refused when the plan compiles, before anything runs.
fn assert_refused_at_compile(call: &str) {
    let failure = compile(&valid_after(call)).unwrap_err();
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.action.plan-function-unavailable"),
        "{call}: {failure:?}"
    );
}
/// The literal `label` the plan's effect sets.
fn effect_label(outcome: Result<ActionHandlerOutcome, ActionHandlerError>) -> String {
    let effects = match outcome {
        Ok(ActionHandlerOutcome::Effects(effects)) => effects,
        other => panic!("an effect expected, got {other:?}"),
    };
    effects[0]
        .mutations
        .iter()
        .find_map(|mutation| match mutation {
            CompiledPlanMutation::Set {
                field,
                value: CompiledPlanValue::Literal { value },
            } if field == "label" => value.as_str().map(str::to_owned),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a literal label expected: {effects:?}"))
}
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
    // A clock call named in the source is refused at compile; one whose name
    // is computed at run time finds no such function in the engine.
    for call in ["timestamp()", "Fn(\"timestamp\").call()"] {
        assert_refused_at_compile(call);
    }
    for call in [
        "read_file(\"private\")",
        "getenv(\"private\")",
        "call(Fn(\"time\" + \"stamp\"))",
        "random()",
    ] {
        assert_eq!(
            evaluate(&valid_after(call), deadline()).unwrap_err(),
            ActionHandlerError::Execution,
            "{call}"
        );
    }
    // The context carries the bound inputs and nothing else. Each plan writes
    // a valid effect whose label says what it found, so a context that
    // exposed claims, records, or any member beside the inputs would commit
    // "exposed" instead of "closed".
    for (member, exposed) in [
        ("ctx.claims", "ctx.claims != ()"),
        ("ctx.records", "ctx.records != ()"),
        ("ctx members", "ctx.keys() != [\"inputs\"]"),
    ] {
        let script = format!(
            "fn calculate(ctx) {{ let seen = if {exposed} {{ \"exposed\" }} else {{ \"closed\" }}; #{{effects:[#{{id:\"item\",set:#{{label:seen}}}}]}} }}"
        );
        assert_eq!(
            effect_label(evaluate(&script, deadline())),
            "closed",
            "{member}"
        );
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
    // The deadline is checked between operations, so a native call that
    // blocks or never returns would outlast it. No such call is reachable:
    // each one is refused at once, before the deadline, and the next call
    // runs normally.
    for call in ["sleep(2)", "Fn(\"sleep\").call(2.0)"] {
        assert_refused_at_compile(call);
    }
    for call in [
        "call(Fn(\"sl\" + \"eep\"), 2)",
        "Fn(\"sl\" + \"eep\").call(2.0)",
        "let text = \"a\"; text.pad(5, \"\")",
    ] {
        assert_eq!(
            evaluate_within(&valid_after(call), Duration::from_millis(250)).unwrap_err(),
            ActionHandlerError::Execution,
            "{call}"
        );
        assert!(matches!(
            evaluate(VALID, deadline()).unwrap(),
            ActionHandlerOutcome::Effects(_)
        ));
    }
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
