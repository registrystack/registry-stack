// SPDX-License-Identifier: Apache-2.0

//! Current named plan wire integrity and backend separation.

use std::time::{Duration, Instant};

use registry_breg::action_handler::{evaluate_action_detailed, ActionHandlerError};
use registry_breg::model::{CompiledAction, CompiledActionInventory, CompiledPlanFunctionKind};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;

fn current_actions_inventory() -> CompiledActionInventory {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-registration-rhai");
    let project = registry_breg::contract::parse_project_yaml(
        &std::fs::read(root.join("registry.yaml")).unwrap(),
    )
    .unwrap();
    let assets = [
        "scripts/register-person.rhai",
        "scripts/register-person-with-registration.rhai",
    ]
    .map(|path| registry_breg::contract::ModuleAssetSource {
        module: None,
        path: path.into(),
        bytes: std::fs::read(root.join(path)).unwrap(),
    });
    registry_breg::compiler::compile_project_with_assets(
        &project,
        &[],
        &assets,
        registry_breg::compiler::CompileProfile::Authoring,
    )
    .unwrap()
    .actions()
    .clone()
}

fn register_person(inventory: &CompiledActionInventory) -> CompiledAction {
    inventory
        .actions
        .iter()
        .find(|action| action.id == "register-person")
        .expect("the frozen inventory carries register-person")
        .clone()
}

#[test]
fn current_plan_inventory_round_trips_canonically() {
    let inventory = current_actions_inventory();
    let action = register_person(&inventory);
    let handler = action
        .handler
        .as_ref()
        .expect("the frozen action declares a handler");
    assert_eq!(handler.kind, CompiledPlanFunctionKind::Rhai);
    assert_eq!(handler.abi, registry_breg::contract::ACTION_PLAN_ABI_V1);
    assert_eq!(handler.rhai_version.as_deref(), Some("1.26.1"));

    let rendered = canonicalize_json(&serde_json::to_value(&inventory).unwrap()).unwrap();
    let decoded: CompiledActionInventory = serde_json::from_slice(&rendered).unwrap();
    assert_eq!(
        canonicalize_json(&serde_json::to_value(decoded).unwrap()).unwrap(),
        rendered
    );
    let document: Value = serde_json::from_slice(&rendered).unwrap();
    let wire = &document["actions"][0]["handler"];
    for private in ["scriptBytes", "moduleBytes", "scriptPath", "modulePath"] {
        assert!(
            wire.get(private).is_none(),
            "private source member {private}"
        );
    }
}

#[test]
fn compiled_plan_refuses_unknown_members() {
    let mut governed = serde_json::to_value(current_actions_inventory()).unwrap();
    let handler = governed["actions"][0]["handler"]
        .as_object_mut()
        .expect("the first action carries a handler");
    handler.insert("wasmModule".to_owned(), Value::String("x.wasm".to_owned()));
    let tampered = serde_json::to_vec(&governed).unwrap();
    assert!(
        serde_json::from_slice::<CompiledActionInventory>(&tampered).is_err(),
        "an unknown compiled handler field must stay refused, not silently ignored"
    );
}

#[test]
fn only_the_handler_kind_expresses_the_wasm_backend() {
    // The compiled handler representation can express the wasm backend, so a
    // future compiler can tag WASM packages without another wire change.
    let rendered = serde_json::to_vec(&CompiledPlanFunctionKind::Wasm).unwrap();
    assert_eq!(rendered, b"\"wasm\"");
    let parsed: CompiledPlanFunctionKind = serde_json::from_slice(b"\"wasm\"").unwrap();
    assert_eq!(parsed, CompiledPlanFunctionKind::Wasm);

    assert!(serde_json::from_slice::<CompiledPlanFunctionKind>(b"\"url\"").is_err());
}

#[test]
fn a_wasm_tag_cannot_execute_rhai_source_bytes() {
    // In a build with the executor feature, evaluation of a wasm-tagged
    // handler reaches the process runtime, so install it and pin the deeper
    // refusal (the frozen Rhai handler carries no module content hash). In a
    // build without the feature, admission refuses the backend itself.
    #[cfg(feature = "wasm")]
    registry_breg::wasm_runtime::install_default().expect("the wasm runtime installs");
    let mut action = register_person(&current_actions_inventory());
    let handler = action
        .handler
        .as_mut()
        .expect("the action declares a handler");
    handler.kind = CompiledPlanFunctionKind::Wasm;
    let mut inputs = serde_json::Map::new();
    inputs.insert(
        "identifier".to_owned(),
        Value::String("0123456789012".to_owned()),
    );
    inputs.insert("given-name".to_owned(), Value::String("Mina".to_owned()));
    let refused =
        evaluate_action_detailed(&action, &inputs, Instant::now() + Duration::from_secs(30))
            .expect_err("a wasm-tagged compiled handler must not execute as Rhai");
    assert_eq!(refused.kind, ActionHandlerError::Source);
}
