// SPDX-License-Identifier: Apache-2.0

//! Compiled handler wire compatibility.
//!
//! The compiled action handler carries its own backend-tagged kind, separate
//! from the change-request planner kind. These tests pin the wire behavior of
//! both kinds against the frozen pre-change package: the old Rhai handler form
//! stays readable and re-serializes to the same canonical bytes, unknown
//! handler fields stay refused, only the handler kind can express the wasm
//! backend, and the runtime refuses to execute a non-Rhai handler kind.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use registry_breg::action_handler::{evaluate_action_detailed, ActionHandlerError};
use registry_breg::model::{
    CompiledAction, CompiledActionHandlerKind, CompiledActionInventory,
    CompiledChangeRequestPlannerKind,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;

fn frozen_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/person-registration-rhai-package")
}

fn frozen_actions_inventory() -> CompiledActionInventory {
    let bytes = fs::read(frozen_package().join("inventories/actions.json"))
        .expect("the frozen package action inventory is present");
    serde_json::from_slice(&bytes).expect("the frozen action inventory still parses")
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
fn old_rhai_handler_wire_stays_readable_and_byte_stable() {
    let inventory = frozen_actions_inventory();
    let action = register_person(&inventory);
    let handler = action
        .handler
        .as_ref()
        .expect("the frozen action declares a handler");
    assert_eq!(handler.kind, CompiledActionHandlerKind::Rhai);
    assert_eq!(handler.abi, registry_breg::contract::ACTION_HANDLER_ABI_V1);
    assert_eq!(handler.rhai_version.as_deref(), Some("1.25.1"));

    // The exact canonical bytes the pre-change compiler wrote must re-emerge
    // from the current types unchanged.
    let rendered = canonicalize_json(&serde_json::to_value(&inventory).unwrap())
        .expect("the inventory renders as canonical JSON");
    let frozen = fs::read(frozen_package().join("inventories/actions.json")).unwrap();
    assert_eq!(
        rendered, frozen,
        "the compiled action inventory must serialize to the frozen bytes"
    );

    // The governed model embeds the same inventory for predecessor inspection.
    let governed = fs::read(frozen_package().join("effective-model.json")).unwrap();
    let governed: Value = serde_json::from_slice(&governed).unwrap();
    let embedded: CompiledActionInventory =
        serde_json::from_value(governed["actionInventory"].clone())
            .expect("the frozen governed model action inventory still parses");
    assert_eq!(embedded, inventory);
}

#[test]
fn old_handler_wire_still_refuses_unknown_fields() {
    let frozen = fs::read(frozen_package().join("inventories/actions.json")).unwrap();
    let mut governed: Value = serde_json::from_slice(&frozen).unwrap();
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
    let rendered = serde_json::to_vec(&CompiledActionHandlerKind::Wasm).unwrap();
    assert_eq!(rendered, b"\"wasm\"");
    let parsed: CompiledActionHandlerKind = serde_json::from_slice(b"\"wasm\"").unwrap();
    assert_eq!(parsed, CompiledActionHandlerKind::Wasm);

    // The compiled planner kind stays Rhai-only: WASM planners have no
    // compiled representation to fall back into.
    assert!(serde_json::from_slice::<CompiledChangeRequestPlannerKind>(b"\"wasm\"").is_err());
    let planner: CompiledChangeRequestPlannerKind = serde_json::from_slice(b"\"rhai\"").unwrap();
    assert_eq!(planner, CompiledChangeRequestPlannerKind::Rhai);
}

#[test]
fn runtime_refuses_to_execute_non_rhai_handler_kinds() {
    // In a build with the executor feature, evaluation of a wasm-tagged
    // handler reaches the process runtime, so install it and pin the deeper
    // refusal (the frozen Rhai handler carries no module content hash). In a
    // build without the feature, admission refuses the backend itself.
    #[cfg(feature = "wasm")]
    registry_breg::wasm_runtime::install_default().expect("the wasm runtime installs");
    let mut action = register_person(&frozen_actions_inventory());
    let handler = action
        .handler
        .as_mut()
        .expect("the action declares a handler");
    handler.kind = CompiledActionHandlerKind::Wasm;
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
