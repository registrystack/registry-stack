// SPDX-License-Identifier: Apache-2.0
//! WASM handler execution through the real evaluation entry: the request
//! envelope, the shared outcome layers, the deadline backstop, and the
//! prepared-module cache. Everything runs against wat guests compiled with
//! the `wat` dev dependency, exactly like the admission and parity suites.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use registry_platform_script::wasm::Budgets;
use serde_json::{json, Map, Value};

use crate::action_handler::{
    evaluate_admitted_action_detailed, ActionHandlerError, ActionHandlerOutcome,
};
use crate::compiler::{compile_project_with_assets, CompileProfile};
use crate::contract::{parse_project_json, ModuleAssetSource};
use crate::model::{CompiledAction, CompiledActionHandler, CompiledActionHandlerKind};
use crate::wasm_runtime::{
    install, installed, shutdown, WasmExecutionBudgets, WasmHandlerRuntime,
    MAXIMUM_RETAINED_PREPARED_MODULES,
};

/// The process runtime is global; serialize every test that touches it.
static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

fn hex_escape(bytes: &[u8]) -> String {
    let mut escaped = String::with_capacity(bytes.len() * 4);
    for byte in bytes {
        escaped.push_str(&format!("\\{byte:02x}"));
    }
    escaped
}

fn compiled_wat(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("guest wat compiles to a binary module")
}

/// A wat guest whose outcome window holds `document` verbatim; the same
/// construction the parity corpus uses.
fn outcome_guest(document: &str) -> String {
    let document = document.as_bytes();
    format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{escaped}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const {len}))
)"#,
        escaped = hex_escape(document),
        len = document.len(),
    )
}

/// A guest that returns its fixed outcome document only when the request
/// bytes start with the v1 envelope member `{"inputs`, and reports a
/// malformed request otherwise. Proves the envelope the runtime builds is
/// the one the handler contract defines.
fn envelope_guarded_outcome_guest(document: &str) -> String {
    let document = document.as_bytes();
    const ENVELOPE_PREFIX: &[u8] = br#"{"inputs"#;
    format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{escaped}")
  (data (i32.const 2048) "{prefix}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32)
    (local $i i32)
    (loop $check
      (if (i32.ne (i32.load8_u (i32.add (local.get $ptr) (local.get $i)))
                  (i32.load8_u (i32.add (i32.const 2048) (local.get $i))))
        (then (return (i32.const 1))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $check (i32.lt_u (local.get $i) (i32.const {prefix_len}))))
    (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const {len}))
)"#,
        escaped = hex_escape(document),
        prefix = hex_escape(ENVELOPE_PREFIX),
        prefix_len = ENVELOPE_PREFIX.len(),
        len = document.len(),
    )
}

/// The person fixture from the parity suite, with its handler switched to a
/// WASM module carrying `module_bytes`.
fn wasm_person_action(module_bytes: &[u8]) -> CompiledAction {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"wasm-runtime","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{"id":"person","primaryDataset":"parity","route":"people","mutationMode":"mutable","fields":[
            {"id":"name","type":"string","maxLength":160,"required":true,"classification":"restricted"},
            {"id":"friend","type":"reference","target":"person","classification":"restricted"}
        ]}],
        "actions":[{"id":"register-person","inputs":[
            {"id":"given-name","apiName":"givenName","type":"string","maxLength":80,"required":true,"classification":"restricted"},
            {"id":"family-name","type":"string","maxLength":80,"classification":"restricted"},
            {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}
        ],"handler":{"kind":"wasm","module":"handlers/guest.wasm","abi":"registry.action-handler/v1","refusals":[{"code":"blank-name","label":"A name is required."}],"writes":[
            {"id":"person","target":{"entity":"person"},"operation":"create","fields":["name","friend"]}
        ]}}],
        "accessProfiles":[{"id":"registrar","default":true,"principalClaim":"principal","permissions":[{"action":"register-person","operations":["invoke"],"targets":[{"entity":"person","rowBoundaries":[]}],"results":["person"]}]}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "handlers/guest.wasm".into(),
            bytes: module_bytes.to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
    .actions()
    .actions[0]
        .clone()
}

fn person_inputs() -> Map<String, Value> {
    json!({"given-name":" Mina ","person":"550e8400-e29b-41d4-a716-446655440000"})
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn request_envelope_is_the_inputs_document() {
    let _guard = INSTALL_LOCK.lock().unwrap();
    // The guest hands back its outcome only when the request starts with
    // `{"inputs`; any other envelope shape is reported malformed.
    let document = r#"{"effects":[{"id":"person","set":{"name":"Mina"}}]}"#;
    let action = wasm_person_action(&compiled_wat(&envelope_guarded_outcome_guest(document)));
    let outcome =
        evaluate_admitted_action_detailed(&action, &person_inputs(), deadline(60)).unwrap();
    let ActionHandlerOutcome::Effects(effects) = outcome else {
        panic!("expected effects");
    };
    assert_eq!(effects[0].id, "person");
}

#[test]
fn wasm_effects_and_refusals_flow_through_the_shared_validator() {
    let _guard = INSTALL_LOCK.lock().unwrap();
    // Accepted effects.
    let document =
        r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":{"fromField":"person"}}}]}"#;
    let action = wasm_person_action(&compiled_wat(&outcome_guest(document)));
    let outcome =
        evaluate_admitted_action_detailed(&action, &person_inputs(), deadline(60)).unwrap();
    let ActionHandlerOutcome::Effects(effects) = outcome else {
        panic!("expected effects");
    };
    assert_eq!(effects.len(), 1);

    // A declared refusal resolves its label from the compiled catalogue.
    let refusal = r#"{"refusal":{"code":"blank-name","field":"given-name"}}"#;
    let action = wasm_person_action(&compiled_wat(&outcome_guest(refusal)));
    let outcome =
        evaluate_admitted_action_detailed(&action, &person_inputs(), deadline(60)).unwrap();
    let ActionHandlerOutcome::Refusal(refusal) = outcome else {
        panic!("expected a refusal");
    };
    assert_eq!(refusal.code, "blank-name");
    assert_eq!(refusal.label, "A name is required.");
    assert_eq!(refusal.field.as_deref(), Some("given-name"));

    // A validator refusal keeps its kind, exactly as the Rhai path reports it.
    let ceiling = r#"{"effects":[{"id":"unknown","set":{"name":"Mina"}}]}"#;
    let action = wasm_person_action(&compiled_wat(&outcome_guest(ceiling)));
    let diagnostic =
        evaluate_admitted_action_detailed(&action, &person_inputs(), deadline(60)).unwrap_err();
    assert_eq!(diagnostic.kind, ActionHandlerError::Ceiling);
    assert_eq!(
        diagnostic.message,
        "Use an id from the handler's declared write slots."
    );
}

#[test]
fn action_deadline_maps_to_the_epoch_backstop() {
    let _guard = INSTALL_LOCK.lock().unwrap();
    // A spinning guest under a 25 ms action deadline is stopped by the epoch
    // deadline and classified exactly like the Rhai path classifies a
    // deadline: ActionHandlerError::Deadline.
    let spin = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32)
    (local $i i32)
    (loop $spin
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $spin))
    (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const 0))
)"#;
    let action = wasm_person_action(&compiled_wat(spin));
    let diagnostic = evaluate_admitted_action_detailed(
        &action,
        &person_inputs(),
        Instant::now() + Duration::from_millis(25),
    )
    .unwrap_err();
    assert_eq!(diagnostic.kind, ActionHandlerError::Deadline);
}

/// A handler fixture for cache tests: only the fields the cache consults
/// matter (identity hash and module bytes).
fn cache_handler_fixture(document: &str) -> CompiledActionHandler {
    use sha2::{Digest, Sha256};
    let bytes = compiled_wat(&outcome_guest(document));
    let digest = Sha256::digest(&bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    CompiledActionHandler {
        kind: CompiledActionHandlerKind::Wasm,
        source_module: None,
        script_path: String::new(),
        module_path: "handlers/guest.wasm".to_owned(),
        abi: "registry.action-handler/v1".to_owned(),
        rhai_version: None,
        script_sha256: None,
        module_sha256: Some(format!("sha256:{hex}")),
        script_bytes: Vec::new(),
        module_bytes: bytes,
        limits: None,
        writes: Vec::new(),
        refusals: BTreeMap::new(),
    }
}

fn cache_runtime() -> WasmHandlerRuntime {
    WasmHandlerRuntime::new(WasmExecutionBudgets::default(), 2).expect("engine starts")
}

#[test]
fn cache_hit_avoids_recompilation() {
    let runtime = cache_runtime();
    let handler = cache_handler_fixture(r#"{"refusal":{"code":"blank-name"}}"#);
    let first = runtime.prepared_module(&handler).unwrap();
    let second = runtime.prepared_module(&handler).unwrap();
    assert_eq!(runtime.preparation_count(), 1);
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn identity_mismatch_recompiles() {
    let runtime = cache_runtime();
    runtime
        .prepared_module(&cache_handler_fixture(
            r#"{"refusal":{"code":"blank-name"}}"#,
        ))
        .unwrap();
    runtime
        .prepared_module(&cache_handler_fixture(r#"{"refusal":{"code":"other"}}"#))
        .unwrap();
    assert_eq!(runtime.preparation_count(), 2);
}

#[test]
fn retained_module_bound_is_enforced() {
    // Bound of 2: A, B, C compiles three times and evicts A; C stays hot;
    // A misses again while C still hits.
    let runtime = cache_runtime();
    let a = cache_handler_fixture(r#"{"refusal":{"code":"a"}}"#);
    let b = cache_handler_fixture(r#"{"refusal":{"code":"b"}}"#);
    let c = cache_handler_fixture(r#"{"refusal":{"code":"c"}}"#);
    runtime.prepared_module(&a).unwrap();
    runtime.prepared_module(&b).unwrap();
    runtime.prepared_module(&c).unwrap();
    assert_eq!(runtime.preparation_count(), 3);
    runtime.prepared_module(&c).unwrap();
    assert_eq!(runtime.preparation_count(), 3);
    runtime.prepared_module(&a).unwrap();
    assert_eq!(runtime.preparation_count(), 4);
}

#[test]
fn configured_budgets_match_the_compile_time_ceiling_and_platform_defaults() {
    assert_eq!(
        WasmExecutionBudgets::DEFAULT_MAX_MODULE_BYTES,
        crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES
    );
    let platform = Budgets::default();
    assert_eq!(
        WasmExecutionBudgets::DEFAULT_MAX_GUEST_MEMORY_BYTES,
        platform.max_guest_memory_bytes
    );
    assert_eq!(
        WasmExecutionBudgets::DEFAULT_MAX_MODULE_BYTES,
        platform.max_module_bytes
    );
    assert_eq!(MAXIMUM_RETAINED_PREPARED_MODULES, 32);
}

/// The operator configuration section maps straight onto the execution
/// budgets, and its defaults ARE the executor defaults the lazy runtime uses.
#[test]
#[cfg(feature = "runtime")]
fn operator_configuration_maps_onto_the_execution_budgets() {
    use crate::runtime_config::{RawWasmExecutionConfig, WasmExecutionConfig};
    let raw: RawWasmExecutionConfig =
        serde_json::from_str(r#"{"maxModuleBytes":5242880,"maxGuestMemoryBytes":1048576}"#)
            .expect("bounded section parses");
    let budgets = WasmExecutionBudgets::from(
        WasmExecutionConfig::from_raw(raw).expect("bounded section validates"),
    );
    assert_eq!(budgets.max_module_bytes, 5_242_880);
    assert_eq!(budgets.max_guest_memory_bytes, 1_048_576);

    let defaulted = WasmExecutionConfig::from_raw(RawWasmExecutionConfig::default())
        .expect("default section validates");
    assert_eq!(
        WasmExecutionBudgets::from(defaulted),
        WasmExecutionBudgets::default()
    );
}

#[test]
fn install_replaces_and_shutdown_clears_the_process_runtime() {
    let _guard = INSTALL_LOCK.lock().unwrap();
    install(
        WasmExecutionBudgets::default(),
        MAXIMUM_RETAINED_PREPARED_MODULES,
    )
    .unwrap();
    assert!(installed());
    shutdown();
    assert!(!installed());
    // The next evaluation lazily builds a fresh default runtime.
    let document = r#"{"refusal":{"code":"blank-name"}}"#;
    let action = wasm_person_action(&compiled_wat(&outcome_guest(document)));
    evaluate_admitted_action_detailed(&action, &person_inputs(), deadline(60)).unwrap();
    assert!(installed());
}
