// SPDX-License-Identifier: Apache-2.0
use registry_breg::{
    action_handler::{evaluate_action, ActionHandlerOutcome},
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_module_json, parse_project_json, ModuleAssetSource},
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
fn project() -> Value {
    json!({
     "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
     "project":{"id":"ordered-proof","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
     "datasets":[{"id":"records"}],
     "recordTypes":[{"id":"entry","route":"entries","primaryDataset":"records","mutationMode":"mutable","fields":[
     {"id":"name","type":"string","maximumLength":32,"required":true,"classification":"internal"},
     {"id":"parent","type":"reference","target":"entry","classification":"internal"}]}],
     "actions":[{"id":"create-pair","execution":{"mode":"immediate"},"inputs":[{"id":"name","type":"string","maximumLength":32,"required":true,"classification":"internal"}],
     "plan":{"type":"fixed","effects":[{"id":"z-result","target":{"recordType":"entry"},"operation":"create","set":{"name":{"fromInput":"name"}}},{"id":"a-result","target":{"recordType":"entry"},"operation":"create","set":{"name":{"fromInput":"name"}}}]}}],
     "accessProfiles":[{"id":"creator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"actions":[{"action":"create-pair","operations":["invoke"],"targets":[{"recordType":"entry","rowBoundaries":"unrestricted"}],"results":["z-result","a-result"]}]}}]
    })
}
fn compile(
    value: Value,
    script: &str,
) -> Result<registry_breg::model::CompiledRegistry, registry_breg::CompileFailure> {
    let source = parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/plan.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
}
#[test]
fn production_compiler_preserves_independent_authored_order() {
    let model = compile(project(), "fn plan(ctx) { #{effects: []} }").unwrap();
    assert_eq!(
        model.actions().actions[0]
            .effects
            .iter()
            .map(|effect| effect.id.as_str())
            .collect::<Vec<_>>(),
        ["z-result", "a-result"]
    );
}
#[test]
fn production_compiler_refuses_forward_and_cyclic_references_and_after() {
    let mut value = project();
    value["actions"][0]["plan"]["effects"][1]["set"]["parent"] = json!({"fromEffect":"z-result"});
    assert!(compile(value.clone(), "fn plan(ctx) { #{effects: []} }").is_ok());
    let mut forward = project();
    forward["actions"][0]["plan"]["effects"][0]["set"]["parent"] = json!({"fromEffect":"a-result"});
    assert!(compile(forward, "fn plan(ctx) { #{effects: []} }").is_err());
    let mut self_reference = project();
    self_reference["actions"][0]["plan"]["effects"][0]["set"]["parent"] =
        json!({"fromEffect":"z-result"});
    assert!(compile(self_reference, "fn plan(ctx) { #{effects: []} }").is_err());
    value["actions"][0]["plan"]["effects"][0]["set"]["parent"] = json!({"fromEffect":"a-result"});
    assert!(compile(value, "fn plan(ctx) { #{effects: []} }").is_err());
    let mut value = project();
    value["actions"][0]["plan"]["effects"][0]["after"] = json!(["a-result"]);
    assert!(parse_project_json(&serde_json::to_vec(&value).unwrap()).is_err());
}
#[test]
fn production_function_evaluator_preserves_order_and_refuses_forward_refs() {
    let mut value = project();
    value["functions"] = json!([{"id":"pair-plan","runtime":"rhai","source":"plans/plan.rhai","entrypoint":"plan","abi":"registry.action-plan/v1","capabilities":[]}]);
    value["actions"][0]["plan"] = json!({"type":"function","function":"pair-plan","inputs":["name"],"writes":[
 {"id":"z-result","target":{"recordType":"entry"},"operation":"create","fields":["name","parent"]},
 {"id":"a-result","target":{"recordType":"entry"},"operation":"create","fields":["name","parent"]}]});
    let script = r#"fn plan(ctx) { #{effects:[#{id:"z-result",set:#{name:ctx.inputs.name}},#{id:"a-result",set:#{name:ctx.inputs.name}}]} }"#;
    let model = compile(value.clone(), script).unwrap();
    let inputs = json!({"name":"entry"}).as_object().unwrap().clone();
    let ActionHandlerOutcome::Effects(effects) = evaluate_action(
        &model.actions().actions[0],
        &inputs,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap() else {
        panic!("effects")
    };
    assert_eq!(
        effects
            .iter()
            .map(|effect| effect.id.as_str())
            .collect::<Vec<_>>(),
        ["z-result", "a-result"]
    );
    let script = r#"fn plan(ctx) { #{effects:[#{id:"a-result",set:#{name:ctx.inputs.name,parent:#{fromEffect:"z-result"}}},#{id:"z-result",set:#{name:ctx.inputs.name}}]} }"#;
    let model = compile(value, script).unwrap();
    assert!(evaluate_action(
        &model.actions().actions[0],
        &inputs,
        Instant::now() + Duration::from_secs(2)
    )
    .is_err());
}

#[test]
fn modules_share_native_record_types_value_types_and_function_asset_provenance() {
    let mut value = project();
    value["recordTypes"] = json!([]);
    value["modules"] = json!([{"id":"records","version":"1"},{"id":"extensions","version":"1"}]);
    value["actions"][0]["plan"] = json!({"type":"function","function":"module-plan","inputs":["name"],"writes":[
        {"id":"z-result","target":{"recordType":"entry"},"operation":"create","fields":["name"]},
        {"id":"a-result","target":{"recordType":"entry"},"operation":"create","fields":["name"]}
    ]});
    let mut reused = value["actions"][0].clone();
    reused["id"] = json!("create-pair-again");
    value["actions"].as_array_mut().unwrap().push(reused);
    let mut permission = value["accessProfiles"][0]["permissions"]["actions"][0].clone();
    permission["action"] = json!("create-pair-again");
    value["accessProfiles"][0]["permissions"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(permission);
    let records = parse_module_json(&serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"records","version":"1",
        "valueTypes":{"name":{"type":"string","maximumLength":32}},
        "recordTypes":[{"id":"entry","route":"entries","primaryDataset":"records","mutationMode":"mutable","fields":[{"id":"name","typeRef":"name","required":true,"classification":"internal"}]}],
        "functions":[{"id":"module-plan","runtime":"rhai","source":"plans/plan.rhai","entrypoint":"plan","abi":"registry.action-plan/v1","capabilities":["evidence"]}]
    })).unwrap()).unwrap();
    let extensions = parse_module_json(&serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"extensions","version":"1","dependencies":["records"],
        "valueTypes":{"note":{"type":"string","maximumLength":64}},
        "extendRecordTypes":[{"recordType":"entry","fields":[{"id":"note","typeRef":"note","classification":"internal"}]}]
    })).unwrap()).unwrap();
    let source = parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let model = compile_project_with_assets(
        &source,
        &[extensions, records],
        &[
            ModuleAssetSource {
                module: Some("records".into()),
                path: "plans/plan.rhai".into(),
                bytes:
                    b"fn plan(ctx) { #{effects:[#{id: \"z-result\",set:#{name:ctx.inputs.name}}]} }"
                        .to_vec(),
            },
            ModuleAssetSource {
                module: None,
                path: "plans/plan.rhai".into(),
                bytes: b"deliberately invalid unrelated project asset".to_vec(),
            },
        ],
        CompileProfile::Authoring,
    )
    .unwrap();
    assert!(model.entities()["entry"].fields.contains_key("note"));
    assert_eq!(model.actions().actions.len(), 2);
    assert!(model.actions().actions.iter().all(|action| {
        action
            .handler
            .as_ref()
            .and_then(|handler| handler.source_module.as_deref())
            == Some("records")
    }));
    assert!(model.actions().actions.iter().all(|action| action
        .handler
        .as_ref()
        .is_some_and(|handler| handler.capabilities.is_empty())));
    assert!(evaluate_action(
        &model.actions().actions[0],
        &json!({"name":"entry"}).as_object().unwrap().clone(),
        Instant::now() + Duration::from_secs(2)
    )
    .is_ok());
}

#[test]
fn fixed_reference_values_require_an_authorized_input_or_created_result() {
    let mut value = project();
    value["actions"][0]["plan"]["effects"][0]["set"]["parent"] =
        json!({"value":"00000000-0000-4000-8000-000000000001"});
    let failure = compile(value.clone(), "fn plan(ctx) { #{effects: []} }").unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|d| d.code == "breg.action.effect-reference-input-required"));
    value["actions"][0]["plan"]["effects"][0]["set"]
        .as_object_mut()
        .unwrap()
        .remove("parent");
    value["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({
        "id":"parent", "type":"reference", "target":"entry", "required":true, "classification":"internal"
    }));
    value["actions"][0]["plan"]["effects"][0]["target"] = json!({"fromInput":"parent"});
    value["actions"][0]["plan"]["effects"][0]["operation"] = json!("patch");
    value["actions"][0]["plan"]["effects"][0]["clear"] = json!(["parent"]);
    compile(value.clone(), "fn plan(ctx) { #{effects: []} }").unwrap();
    value["actions"][0]["plan"]["effects"][0]
        .as_object_mut()
        .unwrap()
        .remove("clear");
    value["actions"][0]["plan"]["effects"][0]["set"]["parent"] = json!({"fromInput":"parent"});
    assert!(compile(value, "fn plan(ctx) { #{effects: []} }").is_ok());
}
