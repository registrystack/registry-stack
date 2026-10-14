// SPDX-License-Identifier: Apache-2.0
#[path = "support/proposal_hooks_model.rs"]
mod model;
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::model::{CompiledActionExecution, CompiledEventOwner};
use serde_json::{json, Value};

fn compile(source: &Value, assets: &[ModuleAssetSource]) -> registry_breg::CompiledRegistry {
    compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap(),
        &[],
        assets,
        CompileProfile::Authoring,
    )
    .unwrap()
}

#[test]
fn proposal_observers_compile_native_owners_fixed_schema_and_reviewed_handlers() {
    let script = b"fn handle(ctx) { #{answer: \"none\"} }";
    let registry = compile(
        &model::source(json!([
            model::url_hook(),
            model::local_hook("local", json!([]))
        ])),
        &[ModuleAssetSource {
            module: None,
            path: "hooks/local.rhai".into(),
            bytes: script.to_vec(),
        }],
    );
    assert_eq!(registry.event_deliveries().deliveries.len(), 2);
    for delivery in &registry.event_deliveries().deliveries {
        assert!(
            matches!(&delivery.owner,CompiledEventOwner::ProposalAction{action} if action=="correct-name")
        );
        assert_eq!(
            delivery.data_schema,
            registry_breg::proposal_hooks::PROPOSAL_EVENT_SCHEMA
        );
        assert!(delivery.projection_fields.is_empty());
        assert!(delivery.principal.is_none());
        assert!(delivery.when.is_none());
        assert!(registry
            .artifacts()
            .get(&delivery.data_schema_artifact_path)
            .is_some());
    }
    let local = registry
        .event_deliveries()
        .deliveries
        .iter()
        .find(|delivery| delivery.event_id == "local")
        .unwrap();
    assert_eq!(local.handler.as_ref().unwrap().bytes, script);
    let CompiledActionExecution::Proposal { proposal } = &registry.actions().actions[0].execution
    else {
        panic!("Proposal")
    };
    assert_eq!(proposal.hooks.len(), 2);
}

#[test]
fn observer_changes_bind_the_package_without_changing_frozen_action_semantics() {
    let original = compile(&model::source(json!([])), &[]);
    let changed = compile(&model::source(json!([model::url_hook()])), &[]);
    assert_eq!(
        original.actions().actions[0].definition_revision,
        changed.actions().actions[0].definition_revision
    );
    assert_ne!(original.revision(), changed.revision());
    assert_ne!(
        original.artifacts().canonical_inventory_bytes().unwrap(),
        changed.artifacts().canonical_inventory_bytes().unwrap()
    );
}

#[test]
fn proposal_observer_declarations_refuse_authority_projection_and_unknown_transitions() {
    for (key, value) in [
        ("phase", json!("before")),
        ("trigger", json!("request-lifecycle")),
        ("principal", json!("clerk")),
        ("projection", json!(["value"])),
        ("when", json!({"type":"fields"})),
    ] {
        let mut hook = model::url_hook();
        hook[key] = value;
        let error = parse_project_json(&serde_json::to_vec(&model::source(json!([hook]))).unwrap())
            .unwrap_err();
        assert!(format!("{error:?}").contains(key));
    }
    for transitions in [
        json!(["approve-request"]),
        json!(["submitted", "submitted"]),
    ] {
        let mut hook = model::url_hook();
        hook["transitions"] = transitions;
        assert!(
            parse_project_json(&serde_json::to_vec(&model::source(json!([hook]))).unwrap())
                .is_err()
        );
    }
    assert!(parse_project_json(
        &serde_json::to_vec(&model::source(json!([
            model::url_hook(),
            model::url_hook()
        ])))
        .unwrap()
    )
    .is_err());
}

#[test]
fn proposal_local_handlers_use_existing_abi_asset_and_build_admission() {
    let source = model::source(json!([model::local_hook("local", json!([]))]));
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let error =
        compile_project_with_assets(&project, &[], &[], CompileProfile::Authoring).unwrap_err();
    assert!(format!("{error:?}").contains("breg.hook.handler-source-missing"));
    let asset = ModuleAssetSource {
        module: None,
        path: "hooks/local.rhai".into(),
        bytes: b"fn other(ctx) { #{} }".to_vec(),
    };
    let error = compile_project_with_assets(&project, &[], &[asset], CompileProfile::Authoring)
        .unwrap_err();
    assert!(format!("{error:?}").contains("breg.hook.handler-entrypoint"));
    #[cfg(not(feature = "wasm"))]
    {
        let mut source = source;
        source["actions"][0]["execution"]["proposal"]["hooks"][0]["handler"] =
            json!({"type":"wasm","module":"hooks/local.wasm","abi":"registry.hook-handler/v1"});
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        let error =
            compile_project_with_assets(&project, &[], &[], CompileProfile::Authoring).unwrap_err();
        assert!(format!("{error:?}").contains("breg.hook.handler-wasm-build-unsupported"));
        assert!(!format!("{error:?}").contains("asset-missing"));
    }
}
