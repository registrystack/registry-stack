// SPDX-License-Identifier: Apache-2.0
//! A governed action declares its handler in the shared hook handler shape.
//!
//! These tests hold the authored spelling of `actions[].handler`: the handler
//! half reads as a shared `HookHandlerSource`, the authorization members
//! `writes` and `refusals` stay this product's own, the member set stays
//! closed, `abi` stays required, the declared backend and its source
//! reference stay paired, and the remote handler kind the shared declaration
//! also offers is refused for an action, which runs in the registry.

use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{
    parse_project_json, ActionHandlerSource, ModuleAssetSource, ACTION_HANDLER_ABI_V1,
};
use registry_breg::diagnostics::{CompileFailure, Diagnostic};
use registry_platform_hooks::HookHandlerSource;
use serde_json::{json, Value};

fn writes() -> Value {
    json!([{
        "id": "person",
        "target": {"entity": "person"},
        "operation": "create",
        "fields": ["person-code", "legal-name"]
    }])
}

fn rhai_handler() -> Value {
    json!({
        "kind": "rhai",
        "script": "scripts/register-person.rhai",
        "abi": ACTION_HANDLER_ABI_V1,
        "writes": writes(),
        "refusals": [{"code": "ineligible", "label": "The person is not eligible"}]
    })
}

fn wasm_handler() -> Value {
    json!({
        "kind": "wasm",
        "module": "wasm/register-person.wasm",
        "abi": ACTION_HANDLER_ABI_V1,
        "writes": writes(),
        "refusals": []
    })
}

fn project_with_handler(handler: Value) -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "action-handler-contract", "version": "1", "defaultLanguage": "en",
                     "canonicalBaseIri": "https://action-handler.example.test"},
        "entities": [{
            "id": "person",
            "primaryDataset": "test-dataset",
            "route": "people",
            "mutationMode": "mutable",
            "fields": [
                {"id": "person-code", "apiName": "personCode", "type": "string", "maxLength": 64,
                 "required": true, "classification": "restricted"},
                {"id": "legal-name", "apiName": "legalName", "type": "string", "maxLength": 160,
                 "required": true, "classification": "restricted"}
            ]
        }],
        "actions": [{
            "id": "register-person",
            "inputs": [
                {"id": "person-code", "apiName": "personCode", "type": "string", "maxLength": 64,
                 "required": true, "classification": "restricted"},
                {"id": "legal-name", "apiName": "legalName", "type": "string", "maxLength": 160,
                 "required": true, "classification": "restricted"}
            ],
            "handler": handler
        }],
        "accessProfiles": [{
            "id": "registrar", "default": true, "principalClaim": "registry_principal",
            "permissions": [{
                "action": "register-person", "operations": ["invoke"],
                "targets": [{"entity": "person", "rowBoundaries": []}],
                "results": ["person"]
            }]
        }]
    })
}

fn parse(handler: Value) -> Result<ActionHandlerSource, CompileFailure> {
    let bytes = serde_json::to_vec(&project_with_handler(handler)).expect("project serializes");
    parse_project_json(&bytes).map(|project| {
        project.actions[0]
            .handler
            .clone()
            .expect("the action declares a handler")
    })
}

/// The refusal a declaration the reader rejects carries, with the code every
/// such refusal shares already asserted.
fn parse_refusal(handler: Value) -> Diagnostic {
    let failure = parse(handler).expect_err("the declaration is refused");
    let diagnostic = failure
        .diagnostics()
        .first()
        .expect("a refusal carries a diagnostic")
        .clone();
    assert_eq!("source.shape.invalid", diagnostic.code);
    diagnostic
}

fn compile_with_assets(handler: Value, assets: &[ModuleAssetSource]) -> Result<(), CompileFailure> {
    let bytes = serde_json::to_vec(&project_with_handler(handler)).expect("project serializes");
    let project = parse_project_json(&bytes).expect("project parses");
    compile_project_with_assets(&project, &[], assets, CompileProfile::Authoring).map(|_| ())
}

fn compile(handler: Value) -> Result<(), CompileFailure> {
    compile_with_assets(
        handler,
        &[ModuleAssetSource {
            module: None,
            path: "scripts/register-person.rhai".to_owned(),
            bytes: br#"fn handle(ctx) { #{effects:[]} }"#.to_vec(),
        }],
    )
}

#[test]
fn an_action_handler_reads_as_a_shared_hook_handler() {
    let rhai = parse(rhai_handler()).expect("a rhai handler parses");
    assert_eq!(
        HookHandlerSource::Rhai {
            script: "scripts/register-person.rhai".to_owned(),
            abi: Some(ACTION_HANDLER_ABI_V1.to_owned()),
        },
        rhai.handler
    );
    assert_eq!(1, rhai.writes.len());
    assert_eq!(1, rhai.refusals.len());

    let wasm = parse(wasm_handler()).expect("a wasm handler parses");
    assert_eq!(
        HookHandlerSource::Wasm {
            module: "wasm/register-person.wasm".to_owned(),
            abi: Some(ACTION_HANDLER_ABI_V1.to_owned()),
        },
        wasm.handler
    );
}

#[test]
fn an_action_handler_round_trips_to_its_authored_shape() {
    for authored in [rhai_handler(), wasm_handler()] {
        let parsed = parse(authored.clone()).expect("the handler parses");
        assert_eq!(
            authored,
            serde_json::to_value(&parsed).expect("the handler serializes")
        );
    }
}

#[test]
fn an_unknown_member_inside_an_action_handler_is_refused() {
    let mut handler = rhai_handler();
    handler
        .as_object_mut()
        .expect("handler object")
        .insert("entrypoint".to_owned(), json!("handle"));
    let refusal = parse_refusal(handler);
    assert_eq!("project.actions[0].handler.entrypoint", refusal.path);
    assert!(
        refusal.message.contains("unknown field `entrypoint`"),
        "the refusal does not name the unknown member: {}",
        refusal.message
    );
}

#[test]
fn an_action_handler_without_an_abi_is_refused() {
    let mut handler = rhai_handler();
    handler
        .as_object_mut()
        .expect("handler object")
        .remove("abi")
        .expect("the authored handler declares an abi");
    let refusal = parse_refusal(handler);
    assert_eq!("project.actions[0].handler", refusal.path);
    assert!(
        refusal.message.contains("missing field `abi`"),
        "the refusal does not name the missing member: {}",
        refusal.message
    );
}

#[test]
fn an_action_handler_source_reference_follows_the_declared_backend() {
    let mut rhai_with_module = rhai_handler();
    rhai_with_module
        .as_object_mut()
        .expect("handler object")
        .insert("module".to_owned(), json!("wasm/register-person.wasm"));
    let refusal = parse_refusal(rhai_with_module);
    assert!(
        refusal.message.contains("unknown field `module`"),
        "a rhai handler still accepts a WASM module: {}",
        refusal.message
    );

    let mut wasm_with_script = wasm_handler();
    wasm_with_script
        .as_object_mut()
        .expect("handler object")
        .insert("script".to_owned(), json!("scripts/register-person.rhai"));
    let refusal = parse_refusal(wasm_with_script);
    assert!(
        refusal.message.contains("unknown field `script`"),
        "a wasm handler still accepts a Rhai script: {}",
        refusal.message
    );

    let mut rhai_without_script = rhai_handler();
    rhai_without_script
        .as_object_mut()
        .expect("handler object")
        .remove("script")
        .expect("the authored handler declares a script");
    let refusal = parse_refusal(rhai_without_script);
    assert!(
        refusal.message.contains("missing field `script`"),
        "a rhai handler compiles without a script: {}",
        refusal.message
    );
}

#[test]
fn a_remote_action_handler_kind_is_refused() {
    let failure = compile_with_assets(
        json!({
            "kind": "url",
            "destinationId": "person-operations",
            "writes": writes(),
            "refusals": []
        }),
        &[],
    )
    .expect_err("an action handler cannot be remote");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "action.handler.kind.unsupported")
        .unwrap_or_else(|| panic!("missing refusal: {:?}", failure.diagnostics()));
    assert_eq!(
        "actions[register-person].handler.kind", diagnostic.path,
        "the refusal names the member the author wrote"
    );
    assert!(
        diagnostic.message.contains("rhai") && diagnostic.message.contains("wasm"),
        "the refusal does not name the kinds an action may declare: {}",
        diagnostic.message
    );
}

#[test]
fn a_rhai_action_handler_still_compiles() {
    compile(rhai_handler()).expect("a rhai action handler compiles");
}
