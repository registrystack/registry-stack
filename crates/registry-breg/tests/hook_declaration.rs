// SPDX-License-Identifier: Apache-2.0
//! Entity hooks are the shared hook contract's declaration shape, narrowed to
//! the Base Registry Engine's trigger and condition vocabulary.
//!
//! These tests hold the authored spelling: `hooks` is the only accepted key,
//! the replaced `events` key is refused by name, a hook reads as a shared
//! `HookDeclaration`, and the phases and handler kinds the engine cannot run
//! are refused rather than compiled into something that never fires.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_module_json, parse_project_json, HookSource};
use registry_breg::diagnostics::CompileFailure;
use registry_platform_hooks::{HookDeclaration, HookHandlerSource, HookPhase};
use serde_json::{json, Value};

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

fn compile(value: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(value).expect("project serializes"))
        .expect("project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
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
fn an_entity_hook_refuses_a_local_handler_kind() {
    let mut hook = url_hook();
    hook["handler"] = json!({"kind": "rhai", "script": "hooks/case.rhai",
                             "abi": "registry.hook-handler/v1"});
    let failure = compile(&project_with_hooks(json!([hook]))).expect_err("rhai is refused");
    assert_diagnostic(&failure, "hook.handler.kind.unsupported", "url");
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
