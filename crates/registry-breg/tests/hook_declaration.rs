// SPDX-License-Identifier: Apache-2.0
//! Entity hooks are the shared hook contract's declaration shape, narrowed to
//! the Base Registry Engine's trigger and condition vocabulary.
//!
//! These tests hold the authored spelling: `hooks` is the only accepted key,
//! the replaced `events` key is refused by name, a hook reads as a shared
//! `HookDeclaration`, and the phases and handler kinds the engine cannot run
//! are refused rather than compiled into something that never fires.

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{
    parse_module_json, parse_project_json, HookSource, ModuleAssetSource,
};
use registry_breg::diagnostics::CompileFailure;
use registry_breg::model::CompiledHookHandlerKind;
use registry_platform_hooks::{HookDeclaration, HookHandlerKind, HookHandlerSource, HookPhase};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn project_with_hooks(hooks: Value) -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "hook-contract", "version": "1", "defaultLanguage": "en",
                     "canonicalBaseIri": "https://hook-contract.example.test"},
        "entities": [{
            "id": "case",
            "primaryDataset": "test-dataset",
            "route": "cases",
            "mutationMode": "mutable",
            "tombstone": true,
            "classification": "internal",
            "fields": [
                {"id": "label", "type": "string", "maxLength": 64, "classification": "public"},
                {"id": "region", "type": "string", "maxLength": 32, "classification": "internal"}
            ],
            "hooks": hooks
        }]
    })
}

fn url_hook() -> Value {
    json!({
        "id": "case-created",
        "phase": "after",
        "trigger": "created",
        "projection": ["label", "region"],
        "when": {"kind": "fields", "afterEquals": {"region": "north"}},
        "handler": {"kind": "url", "destinationId": "case-operations"}
    })
}

const RHAI_HOOK_SOURCE: &str = "fn handle(ctx) { #{\"answer\": \"none\"} }";

fn rhai_asset(path: &str, source: &str) -> ModuleAssetSource {
    ModuleAssetSource {
        module: None,
        path: path.to_owned(),
        bytes: source.as_bytes().to_vec(),
    }
}

fn compile(value: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    compile_with_assets(value, &[])
}

fn compile_with_assets(
    value: &Value,
    assets: &[ModuleAssetSource],
) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(value).expect("project serializes"))
        .expect("project parses");
    compile_project_with_assets(&project, &[], assets, CompileProfile::Authoring)
}

fn parse_failure(value: &Value) -> CompileFailure {
    parse_project_json(&serde_json::to_vec(value).expect("project serializes"))
        .expect_err("the replaced key is refused")
}

fn assert_diagnostic(failure: &CompileFailure, code: &str, needle: &str) {
    let matched = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == code)
        .unwrap_or_else(|| panic!("missing diagnostic {code:?}: {:?}", failure.diagnostics()));
    assert!(
        matched.message.contains(needle),
        "diagnostic {code:?} does not name {needle:?}: {}",
        matched.message
    );
}

#[test]
fn an_entity_declares_hooks_in_the_shared_declaration_shape() {
    let project = parse_project_json(
        &serde_json::to_vec(&project_with_hooks(json!([url_hook()]))).expect("project serializes"),
    )
    .expect("project parses");
    let hook = &project.entities[0].hooks[0];
    assert_eq!("case-created", hook.id);
    assert_eq!(HookPhase::After, hook.phase);
    assert_eq!(
        Some(&HookHandlerSource::Url {
            destination_id: "case-operations".to_owned()
        }),
        hook.handler.as_ref()
    );
}

#[test]
fn a_hook_reads_as_a_shared_hook_declaration() {
    let hook: HookSource = serde_json::from_value(url_hook()).expect("hook parses");
    let shared: HookDeclaration =
        serde_json::from_value(serde_json::to_value(&hook).expect("hook serializes"))
            .expect("a Base Registry Engine hook is a shared hook declaration");
    assert_eq!(hook.id, shared.id);
    assert_eq!(hook.phase, shared.phase);
    assert_eq!(hook.projection, shared.projection);
    assert_eq!(hook.handler.expect("handler declared"), shared.handler);
}

#[test]
fn the_replaced_events_member_is_refused_by_name_in_a_project() {
    let mut project = project_with_hooks(json!([]));
    let entity = project["entities"][0]
        .as_object_mut()
        .expect("entity object");
    entity.remove("hooks");
    entity.insert("events".to_owned(), json!([url_hook()]));
    assert_diagnostic(&parse_failure(&project), "entity.events.removed", "hooks");
}

#[test]
fn the_replaced_events_member_is_refused_by_name_in_a_module() {
    let module = json!({
        "id": "case-events",
        "version": "1",
        "extendEntities": [{"id": "case", "events": [url_hook()]}]
    });
    let failure = parse_module_json(&serde_json::to_vec(&module).expect("module serializes"))
        .expect_err("the replaced key is refused");
    assert_diagnostic(&failure, "entity.events.removed", "hooks");
}

#[test]
fn an_entity_hook_refuses_the_before_phase() {
    let mut hook = url_hook();
    hook["phase"] = json!("before");
    let failure = compile(&project_with_hooks(json!([hook]))).expect_err("before is refused");
    assert_diagnostic(&failure, "hook.phase.unsupported", "after");
}

#[test]
fn a_before_phase_hook_still_refuses_the_url_handler_kind() {
    let mut hook = url_hook();
    hook["phase"] = json!("before");
    let failure = compile(&project_with_hooks(json!([hook]))).expect_err("before url is refused");
    assert_diagnostic(&failure, "hook.handler.kind.unsupported", "before");
}

#[test]
fn an_after_phase_hook_compiles_a_rhai_handler_into_a_local_delivery() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "rhai", "script": "hooks/case.rhai",
                             "abi": "registry.hook-handler/v1"});
    let compiled = compile_with_assets(
        &project_with_hooks(json!([hook])),
        &[rhai_asset("hooks/case.rhai", RHAI_HOOK_SOURCE)],
    )
    .expect("a rhai hook compiles");
    let delivery = &compiled.event_deliveries().deliveries[0];
    assert_eq!(None, delivery.destination_id);
    assert_eq!(HookHandlerKind::Rhai, delivery.handler_kind());
    let handler = delivery.handler.as_ref().expect("handler compiled");
    assert_eq!(CompiledHookHandlerKind::Rhai, handler.kind);
    assert_eq!("registry.hook-handler/v1", handler.abi);
    assert!(
        handler.digest.starts_with("sha256:"),
        "handler digest is not a sha256 spelling: {}",
        handler.digest
    );
    assert_eq!(RHAI_HOOK_SOURCE.as_bytes(), handler.bytes.as_slice());
}

#[test]
fn an_after_phase_rhai_hook_requires_its_script_asset() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "rhai", "script": "hooks/case.rhai",
                             "abi": "registry.hook-handler/v1"});
    let failure = compile(&project_with_hooks(json!([hook]))).expect_err("the asset is missing");
    assert_diagnostic(&failure, "hook.handler.source_missing", "hooks/case.rhai");
}

#[test]
fn an_after_phase_rhai_hook_requires_a_handle_entry_point() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "rhai", "script": "hooks/case.rhai",
                             "abi": "registry.hook-handler/v1"});
    let failure = compile_with_assets(
        &project_with_hooks(json!([hook])),
        &[rhai_asset("hooks/case.rhai", "fn other(ctx) { #{} }")],
    )
    .expect_err("a script without handle is refused");
    assert_diagnostic(&failure, "hook.handler.entrypoint", "handle");
}

#[test]
fn an_after_phase_rhai_hook_refuses_a_handler_abi_version_one_does_not_define() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "rhai", "script": "hooks/case.rhai",
                             "abi": "registry.hook-handler/v2"});
    let failure = compile_with_assets(
        &project_with_hooks(json!([hook])),
        &[rhai_asset("hooks/case.rhai", RHAI_HOOK_SOURCE)],
    )
    .expect_err("an unknown handler abi is refused");
    assert_diagnostic(
        &failure,
        "hook.handler.abi.unsupported",
        "registry.hook-handler/v1",
    );
}

/// A structurally valid handler guest: the platform byte ABI's exact export
/// set, so the module also passes admission in a wasm-enabled build.
fn wasm_guest_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\"answer\":\"none\"}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const 16))
)"#,
    )
    .expect("guest wat compiles")
}

#[test]
fn an_after_phase_wasm_hook_compiles_into_a_local_delivery() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "wasm", "module": "hooks/case.wasm",
                             "abi": "registry.hook-handler/v1"});
    let module = wasm_guest_module();
    let compiled = compile_with_assets(
        &project_with_hooks(json!([hook])),
        &[ModuleAssetSource {
            module: None,
            path: "hooks/case.wasm".to_owned(),
            bytes: module.clone(),
        }],
    )
    .expect("a wasm hook compiles");
    let delivery = &compiled.event_deliveries().deliveries[0];
    assert_eq!(None, delivery.destination_id);
    assert_eq!(HookHandlerKind::Wasm, delivery.handler_kind());
    let handler = delivery.handler.as_ref().expect("handler compiled");
    assert_eq!(CompiledHookHandlerKind::Wasm, handler.kind);
    assert_eq!("registry.hook-handler/v1", handler.abi);
    assert_eq!(module, handler.bytes);
    assert_eq!(
        handler.digest,
        format!("sha256:{}", hex_lower(&Sha256::digest(&module))),
        "the handler identity digest covers the reviewed module bytes"
    );
}

#[test]
fn an_after_phase_wasm_hook_requires_its_module_asset() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "wasm", "module": "hooks/case.wasm",
                             "abi": "registry.hook-handler/v1"});
    let failure = compile(&project_with_hooks(json!([hook]))).expect_err("the asset is missing");
    assert_diagnostic(
        &failure,
        "hook.handler.module_asset_missing",
        "hooks/case.wasm",
    );
}

#[test]
fn an_after_phase_wasm_hook_refuses_module_text() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "wasm", "module": "hooks/case.wasm",
                             "abi": "registry.hook-handler/v1"});
    let failure = compile_with_assets(
        &project_with_hooks(json!([hook])),
        &[ModuleAssetSource {
            module: None,
            path: "hooks/case.wasm".to_owned(),
            // WebAssembly text is not admitted, even though it parses.
            bytes: b"(module)".to_vec(),
        }],
    )
    .expect_err("module text is refused");
    assert_diagnostic(
        &failure,
        "hook.handler.module_invalid",
        "WebAssembly binary",
    );
}

#[test]
fn a_url_hook_still_compiles_with_its_destination_and_no_handler() {
    let compiled = compile(&project_with_hooks(json!([url_hook()]))).expect("a url hook compiles");
    let delivery = &compiled.event_deliveries().deliveries[0];
    assert_eq!(Some("case-operations"), delivery.destination_id.as_deref());
    assert_eq!(HookHandlerKind::Url, delivery.handler_kind());
    assert!(
        delivery.handler.is_none(),
        "a url delivery holds no program"
    );
}

#[test]
fn a_hook_without_a_handler_is_recorded_outside_production_and_refused_in_it() {
    let mut hook = url_hook();
    hook.as_object_mut().expect("hook object").remove("handler");
    let value = project_with_hooks(json!([hook]));
    compile(&value).expect("a recorded-only hook compiles for authoring");

    let project = parse_project_json(&serde_json::to_vec(&value).expect("project serializes"))
        .expect("project parses");
    let failure = compile_project(&project, &[], CompileProfile::Production)
        .expect_err("production requires a delivery");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "event.delivery.required"),
        "missing production delivery diagnostic: {:?}",
        failure.diagnostics()
    );
}
