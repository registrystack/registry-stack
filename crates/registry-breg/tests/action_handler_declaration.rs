// SPDX-License-Identifier: Apache-2.0
//! Named input-bound plan functions have one closed authored contract.

use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource, ACTION_PLAN_ABI_V1};
use serde_json::{json, Value};

fn project() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"plan-contract","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://plans.example.test"},
        "datasets":[{"id":"test"}],
        "recordTypes":[{"id":"person","primaryDataset":"test","route":"people","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":64,"required":true,"classification":"internal"}]}],
        "functions":[{"id":"person-plan","runtime":"rhai","source":"plans/person.rhai","entrypoint":"calculate","abi":ACTION_PLAN_ABI_V1}],
        "actions":[{"id":"register-person","execution":{"mode":"immediate"},
            "inputs":[{"id":"code","type":"string","maximumLength":64,"required":true,"classification":"internal"},
                      {"id":"unbound","type":"string","maximumLength":64,"classification":"restricted"}],
            "plan":{"type":"function","function":"person-plan","inputs":["code"],
                "writes":[{"id":"person","target":{"recordType":"person"},"operation":"create","fields":["code"]}]}}],
        "accessProfiles":[{"id":"registrar","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "permissions":{"actions":[{"action":"register-person","operations":["invoke"],"targets":[{"recordType":"person","rowBoundaries":"unrestricted"}],"results":["person"]}]}}]
    })
}

fn compile(value: Value) -> Result<registry_breg::CompiledRegistry, registry_breg::CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(&value).unwrap())?;
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/person.rhai".into(),
            bytes: br#"fn calculate(ctx) {
            if "unbound" in ctx.inputs { throw "unbound input leaked"; }
            #{effects:[#{id:"person",set:#{code:ctx.inputs.code}}]}
        }"#
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
}

#[test]
fn a_named_entrypoint_receives_only_its_bound_inputs() {
    let registry = compile(project()).unwrap();
    let action = &registry.actions().actions[0];
    assert_eq!(action.handler.as_ref().unwrap().entrypoint, "calculate");
    let inputs = serde_json::from_value(json!({"code":"P-1","unbound":"private"})).unwrap();
    let outcome = registry_breg::action_handler::evaluate_action_detailed(
        action,
        &inputs,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert!(matches!(
        outcome,
        registry_breg::action_handler::ActionHandlerOutcome::Effects(_)
    ));
}

#[test]
fn native_functions_round_trip_without_backend_aliases() {
    let value = project();
    let parsed = parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let mut rendered_value = serde_json::to_value(&parsed).unwrap();
    fn remove_nulls(value: &mut Value) {
        match value {
            Value::Object(members) => {
                members.retain(|_, value| !value.is_null());
                members.values_mut().for_each(remove_nulls);
            }
            Value::Array(items) => items.iter_mut().for_each(remove_nulls),
            _ => {}
        }
    }
    remove_nulls(&mut rendered_value);
    let rendered = serde_json::to_vec(&rendered_value).unwrap();
    let reparsed = parse_project_json(&rendered).unwrap();
    assert_eq!(parsed.functions, reparsed.functions);
    assert_eq!(parsed.actions, reparsed.actions);
}

#[test]
fn named_function_members_are_closed() {
    let mut value = project();
    value["functions"][0]["script"] = json!("plans/person.rhai");
    let failure = parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|d| d.code == "config.unknown-key" && d.path.ends_with(".script")));
}

#[test]
fn abi_and_source_are_required_on_the_named_function() {
    for member in ["abi", "source", "entrypoint"] {
        let mut value = project();
        value["functions"][0]
            .as_object_mut()
            .unwrap()
            .remove(member);
        assert!(
            parse_project_json(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{member}"
        );
    }
}

#[test]
fn retired_inline_handler_and_remote_runtime_are_refused() {
    let mut value = project();
    value["actions"][0]["handler"] = json!({"type":"rhai","script":"plans/person.rhai"});
    assert!(parse_project_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = project();
    value["functions"][0]["runtime"] = json!("url");
    assert!(parse_project_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn source_path_and_abi_fail_at_the_named_function() {
    let mut value = project();
    value["functions"][0]["source"] = json!("plans/person.wasm");
    let failure = compile(value).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|d| d.path == "functions[id=person-plan].source"));
    let mut value = project();
    value["functions"][0]["abi"] = json!("registry.action-handler/v1");
    assert!(compile(value).is_err());
}

#[test]
fn missing_named_function_is_a_compile_time_refusal() {
    let mut value = project();
    value["actions"][0]["plan"]["function"] = json!("absent");
    assert!(compile(value)
        .unwrap_err()
        .diagnostics()
        .iter()
        .any(|d| d.code == "breg.action.function-unknown"));
}
