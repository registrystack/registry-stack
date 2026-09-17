// SPDX-License-Identifier: Apache-2.0
//! Phase 2 exit evidence: WASM and Rhai handler outcomes pass through the
//! same BREG decode layer and the same shared validator.
//!
//! Every parity case drives one outcome document through both backends:
//!
//! - Rhai: a handler script returning the equivalent map, evaluated through
//!   the real evaluation entry (`evaluate_action_detailed`).
//! - WASM: a self-contained inline wat guest whose outcome window holds the
//!   same document as bytes, run through the platform WASM executor, then
//!   decoded by `decode_wasm_outcome` and validated by the same
//!   `validate_proposed_outcome` the Rhai path uses.
//!
//! Parity means identical `ActionHandlerOutcome`s for accepted proposals and
//! identical diagnostics (kind, message, slot, field) for refused ones. The
//! wasm-only tests at the bottom cover what the byte boundary adds (duplicate
//! JSON members, malformed bytes, oversized output rejected before copying)
//! and the one shape the Rhai engine cannot produce (a string over its own
//! size ceiling), which the shared output bound refuses for WASM.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use registry_platform_script::wasm::{Backend, Budgets, Executor, InvokeError};

use super::{decode_wasm_outcome, validate_proposed_outcome, ProposedValue};
use crate::action_handler::{
    evaluate_action_detailed, ActionHandlerDiagnostic, ActionHandlerError, ActionHandlerOutcome,
};
use crate::compiler::{compile_project_with_assets, CompileProfile};
use crate::contract::{parse_project_json, ModuleAssetSource};
use crate::model::CompiledAction;
use serde_json::{json, Map, Value};

/// The fixture with a reference field and three write slots (two creates and
/// one patch from an input field), so reference-envelope and patch-clear
/// cases have real declarations to check against.
fn person_action(script: &str) -> CompiledAction {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"wasm-parity","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{"id":"person","primaryDataset":"parity","route":"people","mutationMode":"mutable","fields":[
            {"id":"name","type":"string","maxLength":160,"required":true,"classification":"restricted"},
            {"id":"friend","type":"reference","target":"person","classification":"restricted"}
        ]}],
        "actions":[{"id":"register-person","inputs":[
            {"id":"given-name","apiName":"givenName","type":"string","maxLength":80,"required":true,"classification":"restricted"},
            {"id":"family-name","type":"string","maxLength":80,"classification":"restricted"},
            {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}
        ],"handler":{"kind":"rhai","script":"handlers/register.rhai","abi":"registry.action-handler/v1","refusals":[{"code":"blank-name","label":"A name is required."}],"writes":[
            {"id":"person","target":{"entity":"person"},"operation":"create","fields":["name","friend"]},
            {"id":"friend","target":{"entity":"person"},"operation":"create","fields":["name","friend"]},
            {"id":"existing","target":{"fromField":"person"},"operation":"patch","fields":["name","friend"]}
        ]}}],
        "accessProfiles":[{"id":"registrar","default":true,"principalClaim":"principal","permissions":[{"action":"register-person","operations":["invoke"],"targets":[{"entity":"person","rowBoundaries":[]}],"results":["person","friend","existing"]}]}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "handlers/register.rhai".into(),
            bytes: script.as_bytes().to_vec(),
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

/// The fixture with int64 and decimal fields, for exact-value parity.
fn record_action(script: &str) -> CompiledAction {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"wasm-parity-records","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{"id":"record","primaryDataset":"parity","route":"records","mutationMode":"mutable","fields":[
            {"id":"label","type":"string","maxLength":160,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"classification":"restricted"}
        ]}],
        "actions":[{"id":"register-record","inputs":[
            {"id":"label","apiName":"displayLabel","type":"string","maxLength":80,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","required":true,"classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"required":true,"classification":"restricted"}
        ],"handler":{"kind":"rhai","script":"handlers/register.rhai","abi":"registry.action-handler/v1","refusals":[{"code":"blank-label","label":"A label is required."}],
            "writes":[{"id":"record","target":{"entity":"record"},"operation":"create","fields":["label","count","amount"]}]
        }}],
        "accessProfiles":[{"id":"writer","default":true,"principalClaim":"principal","permissions":[
            {"action":"register-record","operations":["invoke"],"targets":[{"entity":"record","rowBoundaries":[]}],"results":["record"]}
        ]}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "handlers/register.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
    .actions()
    .actions[0]
        .clone()
}

fn record_inputs() -> Map<String, Value> {
    json!({"label":" Alpha ","count":7,"amount":"123456789012345678.90"})
        .as_object()
        .unwrap()
        .clone()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

/// One shared executor for the whole module: engines are expensive and every
/// call already gets a fresh store and instance.
fn executor() -> &'static Executor {
    static EXECUTOR: OnceLock<Executor> = OnceLock::new();
    EXECUTOR.get_or_init(|| {
        Executor::new(Backend::Native, Budgets::default()).expect("fixed engine config is valid")
    })
}

/// A wat guest whose outcome window holds `document` verbatim: `handle`
/// succeeds, `result_ptr` points at the data segment, and `result_len`
/// reports the document length. Every byte is hex-escaped so arbitrary
/// outcome documents stay valid wat.
fn outcome_guest(document: &[u8]) -> String {
    let mut escaped = String::with_capacity(document.len() * 4);
    for byte in document {
        escaped.push_str(&format!("\\{byte:02x}"));
    }
    format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{escaped}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const {len}))
)"#,
        len = document.len(),
    )
}

/// Run `document` through the platform executor and the shared decode and
/// validation layers, exactly as a WASM handler's outcome bytes would flow.
fn wasm_outcome(
    action: &CompiledAction,
    document: &str,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    let handler = action
        .handler
        .as_ref()
        .expect("fixture actions declare a handler");
    let prepared = executor()
        .prepare(outcome_guest(document.as_bytes()).as_bytes())
        .expect("outcome guest passes ABI validation");
    let invoked = executor()
        .invoke(&prepared, br#"{"inputs":{}}"#)
        .expect("outcome guest call succeeds");
    decode_wasm_outcome(&invoked.output, action.maximum_snapshot_bytes)
        .and_then(|proposed| validate_proposed_outcome(action, handler, proposed))
}

fn rhai_outcome(
    action: &CompiledAction,
    inputs: &Map<String, Value>,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    evaluate_action_detailed(action, inputs, deadline())
}

/// What a parity case expects when both backends refuse the proposal.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Expected {
    Accepted,
    Refused(ActionHandlerError),
}

/// Assert both backends produce the same verdict on one outcome proposal,
/// and that the verdict is the pinned one. The pinned kinds keep the parity
/// check from degenerating into self-comparison: both paths could only drift
/// together by changing the shared validator itself.
fn assert_parity(
    case: &str,
    action: &CompiledAction,
    inputs: &Map<String, Value>,
    document: &str,
    expected: Expected,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    let rhai = rhai_outcome(action, inputs);
    let wasm = wasm_outcome(action, document);
    match expected {
        Expected::Accepted => {
            let (Ok(rhai), Ok(wasm)) = (&rhai, &wasm) else {
                panic!("{case}: expected acceptance, rhai={rhai:?} wasm={wasm:?}");
            };
            assert_eq!(rhai, wasm, "{case}: accepted outcomes differ");
            Ok(rhai.clone())
        }
        Expected::Refused(kind) => {
            let (Err(rhai), Err(wasm)) = (&rhai, &wasm) else {
                panic!("{case}: expected refusal, rhai={rhai:?} wasm={wasm:?}");
            };
            assert_eq!(rhai.kind, wasm.kind, "{case}: refusal kinds differ");
            assert_eq!(
                rhai.message, wasm.message,
                "{case}: refusal messages differ"
            );
            assert_eq!(rhai.slot, wasm.slot, "{case}: refusal slots differ");
            assert_eq!(rhai.field, wasm.field, "{case}: refusal fields differ");
            assert_eq!(
                rhai.evidence_capability, wasm.evidence_capability,
                "{case}: refusal evidence capabilities differ"
            );
            assert_eq!(rhai.kind, kind, "{case}: pinned refusal kind drifted");
            Err(rhai.clone())
        }
    }
}

/// The parity corpus over the person fixture: each row is (case, the outcome
/// document the WASM guest returns, the equivalent Rhai handler body, and
/// the pinned verdict).
fn person_cases() -> Vec<(&'static str, String, String, Expected)> {
    use ActionHandlerError::{Ceiling, Result as ResultKind};
    let script = |body: &str| format!("fn handle(ctx) {{ {body} }}");
    vec![
        // Accepted proposals.
        (
            "create with literal and input reference envelope",
            r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":{"fromField":"person"}}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromField:"person"}}}]} "#),
            Expected::Accepted,
        ),
        (
            "symbolic create chain with patch clear",
            r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":{"fromEffect":"friend"}}},{"id":"friend","set":{"name":"Sam"}},{"id":"existing","clear":["friend"]}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"friend"}}},#{id:"friend",set:#{name:"Sam"}},#{id:"existing",clear:["friend"]}]} "#),
            Expected::Accepted,
        ),
        (
            "declared refusal with field",
            r#"{"refusal":{"code":"blank-name","field":"given-name"}}"#.into(),
            script(r#"#{refusal:#{code:"blank-name",field:"given-name"}}"#),
            Expected::Accepted,
        ),
        (
            "declared refusal without field",
            r#"{"refusal":{"code":"blank-name"}}"#.into(),
            script(r#"#{refusal:#{code:"blank-name"}}"#),
            Expected::Accepted,
        ),
        // Document shape refusals.
        (
            "both effects and refusal",
            r#"{"effects":[{"id":"person","set":{"name":"Mina"}}],"refusal":{"code":"blank-name"}}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}],refusal:#{code:"blank-name"}}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "outcome is not a map",
            r#"42"#.into(),
            script("42"),
            Expected::Refused(ResultKind),
        ),
        (
            "refusal with unknown member",
            r#"{"refusal":{"code":"blank-name","message":"private"}}"#.into(),
            script(r#"#{refusal:#{code:"blank-name",message:"private"}}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "refusal code is not a string",
            r#"{"refusal":{"code":7}}"#.into(),
            script(r#"#{refusal:#{code:7}}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "refusal code is not in the catalogue",
            r#"{"refusal":{"code":"unknown"}}"#.into(),
            script(r#"#{refusal:#{code:"unknown"}}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "refusal field is not a declared input id",
            r#"{"refusal":{"code":"blank-name","field":"givenName"}}"#.into(),
            script(r#"#{refusal:#{code:"blank-name",field:"givenName"}}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "refusal field is not a string",
            r#"{"refusal":{"code":"blank-name","field":7}}"#.into(),
            script(r#"#{refusal:#{code:"blank-name",field:7}}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "effects outcome with unknown member",
            r#"{"effects":[{"id":"person","operation":"create","set":{"name":"Mina"}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",operation:"create",set:#{name:"Mina"}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "effect entry is not a map",
            r#"{"effects":[42]}"#.into(),
            script(r#"#{effects:[42]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "effect without id",
            r#"{"effects":[{"set":{"name":"Mina"}}]}"#.into(),
            script(r#"#{effects:[#{set:#{name:"Mina"}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "effect id is not a string",
            r#"{"effects":[{"id":7,"set":{"name":"Mina"}}]}"#.into(),
            script(r#"#{effects:[#{id:7,set:#{name:"Mina"}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "write slot emitted twice",
            r#"{"effects":[{"id":"person","set":{"name":"Mina"}},{"id":"person","set":{"name":"Sam"}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina"}},#{id:"person",set:#{name:"Sam"}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "set is not a map",
            r#"{"effects":[{"id":"person","set":"Mina"}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:"Mina"}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "set value is null",
            r#"{"effects":[{"id":"person","set":{"name":null}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:()}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "set value is a float",
            r#"{"effects":[{"id":"person","set":{"name":1.5}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:1.5}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "backend value with no outcome meaning",
            // A JSON integer beyond i64 and a Rhai char both decode to the
            // same inexpressible proposal value.
            r#"{"effects":[{"id":"person","set":{"name":9223372036854775808}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:'x'}}]}"#),
            Expected::Refused(ResultKind),
        ),
        // Slot and ceiling refusals.
        (
            "empty effects list",
            r#"{"effects":[]}"#.into(),
            script(r#"#{effects:[]}"#),
            Expected::Refused(Ceiling),
        ),
        (
            "unknown write slot",
            r#"{"effects":[{"id":"unknown","set":{"name":"Mina"}}]}"#.into(),
            script(r#"#{effects:[#{id:"unknown",set:#{name:"Mina"}}]}"#),
            Expected::Refused(Ceiling),
        ),
        (
            "undeclared field in set",
            r#"{"effects":[{"id":"person","set":{"nickname":"Mina"}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{nickname:"Mina"}}]}"#),
            Expected::Refused(Ceiling),
        ),
        (
            "create slot missing a required field",
            r#"{"effects":[{"id":"person","set":{"friend":{"fromField":"person"}}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{friend:#{fromField:"person"}}}]}"#),
            Expected::Refused(Ceiling),
        ),
        (
            "patch clear of a required field",
            r#"{"effects":[{"id":"existing","clear":["name"]}]}"#.into(),
            script(r#"#{effects:[#{id:"existing",clear:["name"]}]}"#),
            Expected::Refused(Ceiling),
        ),
        (
            "create slot clears a field",
            r#"{"effects":[{"id":"person","set":{"name":"Mina"},"clear":["friend"]}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina"},clear:["friend"]}]}"#),
            Expected::Refused(Ceiling),
        ),
        // Reference-envelope refusals.
        (
            "reference envelope is a plain string",
            r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":"550e8400-e29b-41d4-a716-446655440000"}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:"550e8400-e29b-41d4-a716-446655440000"}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "reference envelope names an undeclared fromField",
            r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":{"fromField":"given-name"}}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromField:"given-name"}}}]}"#),
            Expected::Refused(Ceiling),
        ),
        (
            "reference envelope names an unemitted fromEffect",
            r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":{"fromEffect":"missing"}}}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"missing"}}}]}"#),
            Expected::Refused(ResultKind),
        ),
        (
            "reference envelope points at a patch slot",
            r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":{"fromEffect":"existing"}}},{"id":"existing","clear":["friend"]}]}"#.into(),
            script(r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"existing"}}},#{id:"existing",clear:["friend"]}]}"#),
            Expected::Refused(Ceiling),
        ),
    ]
}

#[test]
fn person_outcome_corpus_parity() {
    for (case, document, script, expected) in person_cases() {
        let action = person_action(&script);
        // The pinned verdict is the assertion; the returned value is only
        // for callers that inspect an accepted outcome.
        let _ = assert_parity(case, &action, &person_inputs(), &document, expected);
    }
}

/// The pinned diagnostic for a representative refusal, proving the parity
/// runner compares real diagnostics, not just kinds.
#[test]
fn refused_proposals_carry_identical_pinned_diagnostics() {
    for (case, document, script, kind, pinned_message) in [
        (
            "unknown write slot",
            r#"{"effects":[{"id":"unknown","set":{"name":"Mina"}}]}"#,
            r#"fn handle(ctx) { #{effects:[#{id:"unknown",set:#{name:"Mina"}}]} }"#,
            ActionHandlerError::Ceiling,
            "Use an id from the handler's declared write slots.",
        ),
        (
            "set value is null",
            r#"{"effects":[{"id":"person","set":{"name":null}}]}"#,
            r#"fn handle(ctx) { #{effects:[#{id:"person",set:#{name:()}}]} }"#,
            ActionHandlerError::Result,
            "Set a non-null value; use clear only for optional patch fields.",
        ),
    ] {
        let action = person_action(script);
        let diagnostic = assert_parity(
            case,
            &action,
            &person_inputs(),
            document,
            Expected::Refused(kind),
        )
        .unwrap_err();
        assert_eq!(
            diagnostic.message, pinned_message,
            "{case}: message drifted"
        );
    }
}

#[test]
fn exact_int64_and_decimal_string_values_survive_both_backends() {
    let document = r#"{"effects":[{"id":"record","set":{"label":"Alpha","count":9223372036854775807,"amount":"123456789012345678.90"}}]}"#;
    let script = r#"fn handle(ctx) { #{effects:[#{id:"record",set:#{label:"Alpha",count:9223372036854775807,amount:"123456789012345678.90"}}]} }"#;
    let action = record_action(script);
    let outcome = assert_parity(
        "int64 and decimal exactness",
        &action,
        &record_inputs(),
        document,
        Expected::Accepted,
    )
    .unwrap();
    let ActionHandlerOutcome::Effects(effects) = outcome else {
        panic!("expected effects");
    };
    let mutations = &effects[0].mutations;
    let literal = |field: &str| {
        mutations
            .iter()
            .find_map(|mutation| match mutation {
                crate::model::CompiledActionMutation::Set {
                    field: name,
                    value: crate::model::CompiledActionValue::Literal { value },
                } if name == field => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected a literal for {field}"))
    };
    assert_eq!(literal("count"), json!(9223372036854775807i64));
    assert_eq!(literal("amount"), json!("123456789012345678.90"));
}

#[test]
fn int64_field_refuses_floats_identically() {
    let document =
        r#"{"effects":[{"id":"record","set":{"label":"Alpha","count":1.5,"amount":"1.00"}}]}"#;
    let script = r#"fn handle(ctx) { #{effects:[#{id:"record",set:#{label:"Alpha",count:1.5,amount:"1.00"}}]} }"#;
    let action = record_action(script);
    let _ = assert_parity(
        "float for an int64 field",
        &action,
        &record_inputs(),
        document,
        Expected::Refused(ActionHandlerError::Result),
    );
}

/// Both decoders turn the same document into the same proposal: the Rhai
/// side through the dynamic conversion, the WASM side through the checked
/// byte parse. This is the decode-layer half of parity, independent of
/// validation.
#[test]
fn decode_layer_produces_identical_proposals() {
    for (case, document) in [
        (
            "effects document",
            r#"{"effects":[{"id":"person","set":{"name":"Mina","friend":{"fromField":"person"}}}]}"#,
        ),
        (
            "refusal document",
            r#"{"refusal":{"code":"blank-name","field":"given-name"}}"#,
        ),
        ("not a map", r#"42"#),
        (
            "unknown members",
            r#"{"outcome":true,"refusal":{"code":"blank-name"}}"#,
        ),
    ] {
        let value: Value = serde_json::from_str(document).unwrap();
        let rhai_document = super::rhai_document(
            crate::rhai_planner::json_to_dynamic(&value, 0).expect("document converts"),
        );
        let rhai = super::decode_document(rhai_document);
        let wasm = decode_wasm_outcome(document.as_bytes(), u32::MAX);
        assert_eq!(
            rhai.is_ok(),
            wasm.is_ok(),
            "{case}: decode acceptance differs"
        );
        match (rhai, wasm) {
            (Ok(rhai), Ok(wasm)) => assert_eq!(rhai, wasm, "{case}: proposals differ"),
            (Err(rhai), Err(wasm)) => assert_eq!(rhai, wasm, "{case}: diagnostics differ"),
            _ => unreachable!("{case}: acceptance already compared"),
        }
    }
}

/// Duplicate JSON members are refused before the proposal exists. A Rhai map
/// cannot hold two members with one name, so the ambiguity the check guards
/// against is unproducible there; the assertion documents that asymmetry.
#[test]
fn duplicate_json_members_are_refused_at_decode() {
    let bytes = br#"{"refusal":{"code":"blank-name","code":"blank-name"}}"#;
    let diagnostic = decode_wasm_outcome(bytes, u32::MAX).unwrap_err();
    assert_eq!(diagnostic.kind, ActionHandlerError::Result);
    assert_eq!(
        diagnostic.message,
        "Return the handler outcome as a JSON object without duplicate members."
    );
    // The same document without the duplicate decodes for both backends.
    let unambiguous = br#"{"refusal":{"code":"blank-name"}}"#;
    assert!(decode_wasm_outcome(unambiguous, u32::MAX).is_ok());
}

#[test]
fn malformed_outcome_bytes_are_refused_at_decode() {
    for bytes in [
        br#"{"effects":"#.as_slice(),
        b"\"".as_slice(),
        b"{".as_slice(),
    ] {
        let diagnostic = decode_wasm_outcome(bytes, u32::MAX).unwrap_err();
        assert_eq!(diagnostic.kind, ActionHandlerError::Result, "{bytes:?}");
    }
}

/// The platform executor refuses an oversized outcome before allocating or
/// copying any bytes, so no oversized document can reach the decode layer.
#[test]
fn oversized_outcome_is_rejected_before_decoding() {
    let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const 999999999))
)"#;
    let prepared = executor()
        .prepare(wat.as_bytes())
        .expect("guest passes ABI validation");
    match executor().invoke(&prepared, b"x").unwrap_err() {
        InvokeError::OutputTooLarge { len, max } => {
            assert_eq!(len, 999_999_999);
            assert_eq!(max, 1024 * 1024);
        }
        error => panic!("wrong executor error: {error}"),
    }
}

/// The shared per-string ceiling refuses a value no backend may plan with.
/// The Rhai engine cannot produce it (its own string ceiling fires first,
/// during execution), so this is the WASM-visible half of the same shared
/// rule the Rhai decode applies to the values it can receive.
#[test]
fn shared_output_bound_refuses_oversized_strings() {
    let oversized = "a".repeat(crate::rhai_planner::MAXIMUM_STRING_BYTES + 1);
    let document = format!(r#"{{"effects":[{{"id":"record","set":{{"label":"{oversized}"}}}}]}}"#);
    let action = record_action(r#"fn handle(ctx) { 42 }"#);
    let handler = action
        .handler
        .as_ref()
        .expect("fixture actions declare a handler");
    // The decode layer settles only the document shape; the oversized value
    // is refused by the shared validator, at the same position and with the
    // same kind the Rhai decode path would refuse it.
    let proposed = decode_wasm_outcome(document.as_bytes(), action.maximum_snapshot_bytes)
        .expect("decode settles document shape only");
    let diagnostic = validate_proposed_outcome(&action, handler, proposed)
        .expect_err("oversized string must be refused");
    assert_eq!(diagnostic.kind, ActionHandlerError::Resource);
    assert_eq!(diagnostic.slot.as_deref(), Some("record"));
    assert_eq!(diagnostic.field.as_deref(), Some("label"));

    // The snapshot bound itself is one function whatever backend produced
    // the document: a budget the document cannot fit inside is refused.
    let proposal = ProposedValue::Object(vec![(
        "effects".to_owned(),
        ProposedValue::Array(vec![ProposedValue::Object(vec![(
            "id".to_owned(),
            ProposedValue::Str("record".to_owned()),
        )])]),
    )]);
    assert!(super::bound_document(&proposal, action.maximum_snapshot_bytes).is_ok());
    let oversized_proposal =
        ProposedValue::Object(vec![("refusal".to_owned(), ProposedValue::Str(oversized))]);
    assert_eq!(
        super::bound_document(&oversized_proposal, 64).unwrap_err(),
        ActionHandlerError::Resource
    );
}
