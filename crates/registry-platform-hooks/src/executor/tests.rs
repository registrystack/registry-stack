// SPDX-License-Identifier: Apache-2.0
//! The local hook executor: identity binding, the envelope the entry point
//! receives, the canonical answer, and one flip test for every budget that
//! bounds a local run.
//!
//! A flip test pins a budget by proving both sides of it: the largest input
//! the budget admits is accepted, and the next one up is refused with the
//! category the shared error table assigns.

use std::time::Duration;

use serde_json::json;

use super::{
    program_digest, LocalHookHandler, LocalHookHandlers, LocalHookProgram, LocalHookProgramRefused,
};
use crate::{ErrorCategory, HookHandlerKind, HOOK_HANDLER_ABI_V1, MAX_OUTPUT_BYTES};

const PACKAGE_REVISION: &str = "hook-executor-tests";
const DELIVERY_ID: &str = "case-created";

fn program(kind: HookHandlerKind, bytes: &[u8]) -> LocalHookProgram {
    LocalHookProgram::new(
        kind,
        HOOK_HANDLER_ABI_V1,
        &program_digest(bytes),
        bytes.to_vec(),
        Duration::from_secs(5),
        1,
    )
    .expect("the program is admitted")
}

fn handlers_with(program: LocalHookProgram) -> LocalHookHandlers {
    let mut handlers = LocalHookHandlers::new(PACKAGE_REVISION);
    handlers.insert(DELIVERY_ID, program);
    handlers
}

fn bound(handlers: &LocalHookHandlers, program: &LocalHookProgram) -> LocalHookHandler {
    handlers
        .resolve(
            program.kind(),
            DELIVERY_ID,
            PACKAGE_REVISION,
            program.digest(),
        )
        .expect("the running package holds the bound program")
}

/// The captured envelope shape a hook delivery carries, reduced to the
/// members these tests read. The worker hands the bytes through unchanged.
fn envelope() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "specversion": "1.0",
        "id": "0192f0d6-1b8c-7c2f-9f47-9f5a0f2a4b1c",
        "type": "case.created",
        "data": {"label": "north"}
    }))
    .expect("envelope serializes")
}

// ---------------------------------------------------------------------------
// Identity binding
// ---------------------------------------------------------------------------

const NONE_ANSWER_SCRIPT: &[u8] = br#"fn handle(ctx) { #{"answer": "none"} }"#;

#[test]
fn a_program_digest_is_sha256_over_the_bytes_in_lowercase_hex() {
    assert_eq!(
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        program_digest(b"")
    );
}

#[test]
fn a_local_delivery_binds_to_its_reviewed_program() {
    let admitted = program(HookHandlerKind::Rhai, NONE_ANSWER_SCRIPT);
    let handlers = handlers_with(admitted.clone());
    let handler = bound(&handlers, &admitted);
    assert_eq!(admitted.digest(), handler.program().digest());
    assert_eq!(Duration::from_secs(5), handler.program().attempt_timeout());
    assert_eq!(1, handler.program().maximum_attempts());
}

#[test]
fn a_delivery_from_another_package_revision_binds_to_nothing() {
    let admitted = program(HookHandlerKind::Rhai, NONE_ANSWER_SCRIPT);
    let handlers = handlers_with(admitted.clone());
    assert!(handlers
        .resolve(
            HookHandlerKind::Rhai,
            DELIVERY_ID,
            "some-other-revision",
            admitted.digest()
        )
        .is_none());
}

#[test]
fn a_delivery_naming_another_program_digest_binds_to_nothing() {
    let admitted = program(HookHandlerKind::Rhai, NONE_ANSWER_SCRIPT);
    let handlers = handlers_with(admitted);
    assert!(handlers
        .resolve(
            HookHandlerKind::Rhai,
            DELIVERY_ID,
            PACKAGE_REVISION,
            &format!("sha256:{}", "0".repeat(64)),
        )
        .is_none());
}

#[test]
fn a_delivery_naming_another_handler_kind_binds_to_nothing() {
    let admitted = program(HookHandlerKind::Rhai, NONE_ANSWER_SCRIPT);
    let handlers = handlers_with(admitted.clone());
    assert!(handlers
        .resolve(
            HookHandlerKind::Wasm,
            DELIVERY_ID,
            PACKAGE_REVISION,
            admitted.digest()
        )
        .is_none());
}

#[test]
fn a_delivery_naming_another_compiled_delivery_binds_to_nothing() {
    let admitted = program(HookHandlerKind::Rhai, NONE_ANSWER_SCRIPT);
    let handlers = handlers_with(admitted.clone());
    assert!(handlers
        .resolve(
            HookHandlerKind::Rhai,
            "other",
            PACKAGE_REVISION,
            admitted.digest()
        )
        .is_none());
}

#[test]
fn a_program_whose_recorded_digest_does_not_cover_its_bytes_is_never_admitted() {
    let digest = program_digest(NONE_ANSWER_SCRIPT);
    // The same recorded digest over different bytes is never admitted, so a
    // substituted program cannot inherit another program's retained rows.
    assert_eq!(
        LocalHookProgramRefused::DigestMismatch,
        LocalHookProgram::new(
            HookHandlerKind::Rhai,
            HOOK_HANDLER_ABI_V1,
            &digest,
            b"fn handle(ctx) { () }".to_vec(),
            Duration::from_secs(5),
            1,
        )
        .expect_err("a substituted program is refused")
    );
}

#[test]
fn a_program_speaking_another_handler_abi_is_never_admitted() {
    assert_eq!(
        LocalHookProgramRefused::UnsupportedAbi,
        LocalHookProgram::new(
            HookHandlerKind::Rhai,
            "registry.hook-handler/v2",
            &program_digest(NONE_ANSWER_SCRIPT),
            NONE_ANSWER_SCRIPT.to_vec(),
            Duration::from_secs(5),
            1,
        )
        .expect_err("another ABI is refused")
    );
}

#[test]
fn a_url_handler_is_never_admitted_as_a_local_program() {
    assert_eq!(
        LocalHookProgramRefused::NotLocal,
        LocalHookProgram::new(
            HookHandlerKind::Url,
            HOOK_HANDLER_ABI_V1,
            &program_digest(b""),
            Vec::new(),
            Duration::from_secs(5),
            1,
        )
        .expect_err("a url kind is not local")
    );
}

fn run(
    kind: HookHandlerKind,
    bytes: &[u8],
    envelope: &[u8],
    remaining: Duration,
) -> Result<Vec<u8>, ErrorCategory> {
    let admitted = program(kind, bytes);
    let handlers = handlers_with(admitted.clone());
    bound(&handlers, &admitted).run_blocking(envelope, remaining)
}

#[cfg(not(feature = "rhai"))]
#[test]
fn a_rhai_program_in_a_build_without_the_engine_is_a_source_refusal() {
    assert_eq!(
        Err(ErrorCategory::Source),
        run(
            HookHandlerKind::Rhai,
            NONE_ANSWER_SCRIPT,
            &envelope(),
            Duration::from_secs(5)
        )
    );
}

#[cfg(not(feature = "wasm"))]
#[test]
fn a_wasm_program_in_a_build_without_the_engine_is_a_source_refusal() {
    assert_eq!(
        Err(ErrorCategory::Source),
        run(
            HookHandlerKind::Wasm,
            b"\0asm",
            &envelope(),
            Duration::from_secs(5)
        )
    );
}

// ---------------------------------------------------------------------------
// Rhai
// ---------------------------------------------------------------------------

#[cfg(feature = "rhai")]
mod rhai_engine {
    use super::*;
    use crate::executor::rhai::encode_rhai_answer;
    use crate::executor::{compile_rhai_hook, RHAI_HOOK_MAX_MAP_ENTRIES};
    use serde_json::Value;

    fn run_rhai(
        source: &str,
        envelope: &[u8],
        remaining: Duration,
    ) -> Result<Vec<u8>, ErrorCategory> {
        run(
            HookHandlerKind::Rhai,
            source.as_bytes(),
            envelope,
            remaining,
        )
    }

    #[test]
    fn a_rhai_handler_answers_with_the_canonical_message() {
        let answer = run_rhai(
            r#"fn handle(ctx) { #{"answer": "none"} }"#,
            &envelope(),
            Duration::from_secs(5),
        )
        .expect("the reviewed script answers");
        assert_eq!(br#"{"answer":"none"}"#.as_slice(), answer.as_slice());
    }

    #[test]
    fn a_rhai_handler_receives_the_envelope_as_its_one_argument() {
        let answer = run_rhai(
            r#"fn handle(ctx) {
                 if ctx.type == "case.created" && ctx.data.label == "north" {
                     #{"answer": "none"}
                 } else {
                     throw "unexpected envelope";
                 }
               }"#,
            &envelope(),
            Duration::from_secs(5),
        )
        .expect("the reviewed script reads the envelope");
        assert_eq!(br#"{"answer":"none"}"#.as_slice(), answer.as_slice());
    }

    #[test]
    fn a_rhai_handler_that_returns_nothing_answers_empty() {
        let answer = run_rhai("fn handle(ctx) { () }", &envelope(), Duration::from_secs(5))
            .expect("the reviewed script answers");
        assert!(answer.is_empty(), "an absent answer carries no bytes");
    }

    #[test]
    fn a_script_without_the_entry_point_is_a_source_refusal() {
        assert_eq!(
            Err(ErrorCategory::Source),
            run_rhai("fn other(ctx) { () }", &envelope(), Duration::from_secs(5))
        );
    }

    #[test]
    fn a_script_that_fails_is_an_execution_refusal() {
        assert_eq!(
            Err(ErrorCategory::Execution),
            run_rhai(
                r#"fn handle(ctx) { throw "no" }"#,
                &envelope(),
                Duration::from_secs(5)
            )
        );
    }

    /// No product helper is registered: a program calling one fails to run
    /// rather than reaching product code.
    #[test]
    fn a_script_calling_a_product_helper_is_an_execution_refusal() {
        assert_eq!(
            Err(ErrorCategory::Execution),
            run_rhai(
                r#"fn handle(ctx) { join(["a", "b"], ","); #{"answer": "none"} }"#,
                &envelope(),
                Duration::from_secs(5),
            )
        );
    }

    #[test]
    fn the_compile_check_admits_one_handle_entry_point_and_refuses_eval() {
        assert!(compile_rhai_hook(r#"fn handle(ctx) { #{"answer": "none"} }"#).is_ok());
        assert!(compile_rhai_hook("fn other(ctx) { () }").is_err());
        assert!(compile_rhai_hook(r#"fn handle(ctx) { eval("1") }"#).is_err());
    }

    /// The answer ceiling, at the byte. The value is built directly rather
    /// than returned by a script, because the script data budgets sit far
    /// below this ceiling and would refuse the oversized case for the wrong
    /// reason.
    #[test]
    fn the_rhai_answer_ceiling_admits_the_largest_answer_and_refuses_one_byte_more() {
        // `{"answer":"refusal","refusal":{"code":"<padding>"}}` canonicalizes
        // to a fixed frame plus the padding, so the padding length sets the
        // exact size.
        let frame = br#"{"answer":"refusal","refusal":{"code":""}}"#.len();
        for (padding, expected) in [
            (MAX_OUTPUT_BYTES - frame, None),
            (MAX_OUTPUT_BYTES - frame + 1, Some(ErrorCategory::Resource)),
        ] {
            let mut refusal = rhai::Map::new();
            refusal.insert("code".into(), rhai::Dynamic::from("a".repeat(padding)));
            let mut answer = rhai::Map::new();
            answer.insert("answer".into(), rhai::Dynamic::from("refusal"));
            answer.insert("refusal".into(), rhai::Dynamic::from(refusal));
            let encoded = encode_rhai_answer(&rhai::Dynamic::from(answer));
            match expected {
                None => assert_eq!(
                    MAX_OUTPUT_BYTES,
                    encoded.expect("an answer at the ceiling is admitted").len()
                ),
                Some(category) => assert_eq!(Err(category), encoded),
            }
        }
    }

    /// The attempt timeout, flipped around the same script.
    #[test]
    fn the_rhai_attempt_timeout_admits_a_script_inside_it_and_refuses_one_that_outruns_it() {
        // The loop stays well inside the fixed operation budget, so the only
        // difference between the two runs below is the attempt timeout.
        let script = r#"fn handle(ctx) {
             let total = 0;
             for i in 0..8000 { total += i; }
             #{"answer": "none"}
           }"#;
        assert!(
            run_rhai(script, &envelope(), Duration::from_secs(30)).is_ok(),
            "the script finishes inside a generous budget"
        );
        assert_eq!(
            Err(ErrorCategory::Deadline),
            run_rhai(script, &envelope(), Duration::from_millis(1))
        );
    }

    /// The operation budget, flipped around the loop bound that crosses it.
    /// The budget is a fixed profile constant, not operator configuration.
    #[test]
    fn the_rhai_operation_budget_admits_a_bounded_loop_and_refuses_a_runaway_one() {
        let bounded = r#"fn handle(ctx) {
             let total = 0;
             for i in 0..1000 { total += i; }
             #{"answer": "none"}
           }"#;
        assert!(
            run_rhai(bounded, &envelope(), Duration::from_secs(30)).is_ok(),
            "a bounded loop stays inside the operation budget"
        );
        let runaway = r#"fn handle(ctx) {
             let total = 0;
             loop { total += 1; }
           }"#;
        assert_eq!(
            Err(ErrorCategory::Resource),
            run_rhai(runaway, &envelope(), Duration::from_secs(30))
        );
    }

    /// The envelope conversion budgets, flipped around the map-entry bound.
    #[test]
    fn the_rhai_envelope_bounds_admit_the_widest_object_and_refuse_one_member_more() {
        for (members, expected) in [
            (RHAI_HOOK_MAX_MAP_ENTRIES, None),
            (RHAI_HOOK_MAX_MAP_ENTRIES + 1, Some(ErrorCategory::Resource)),
        ] {
            let data: serde_json::Map<String, Value> = (0..members)
                .map(|index| (format!("f{index}"), Value::from(index as i64)))
                .collect();
            let envelope = serde_json::to_vec(&json!({"data": data})).expect("envelope serializes");
            let outcome = run_rhai(
                r#"fn handle(ctx) { #{"answer": "none"} }"#,
                &envelope,
                Duration::from_secs(30),
            );
            match expected {
                None => assert!(outcome.is_ok(), "an object at the bound is converted"),
                Some(category) => assert_eq!(Err(category), outcome),
            }
        }
    }

    /// A number the program cannot hold as an integer is the product's
    /// envelope fault, not the program's.
    #[test]
    fn an_envelope_with_a_fractional_number_is_a_source_refusal() {
        let envelope = serde_json::to_vec(&json!({"data": {"ratio": 0.5}})).expect("serializes");
        assert_eq!(
            Err(ErrorCategory::Source),
            run_rhai(
                r#"fn handle(ctx) { () }"#,
                &envelope,
                Duration::from_secs(5)
            )
        );
    }
}

// ---------------------------------------------------------------------------
// WASM
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm")]
mod wasm_engine {
    use std::sync::Arc;

    use super::*;
    use crate::executor::{Backend, WasmHookBudgets, WasmHookRuntime};

    const DEFAULT_BUDGETS: WasmHookBudgets = WasmHookBudgets {
        max_module_bytes: 8 * 1024 * 1024,
        max_guest_memory_bytes: 64 * 1024 * 1024,
    };

    fn runtime(budgets: WasmHookBudgets) -> Arc<WasmHookRuntime> {
        Arc::new(WasmHookRuntime::new(budgets, Backend::Pulley).expect("the runtime starts"))
    }

    fn run_wasm(
        runtime: &Arc<WasmHookRuntime>,
        module: &[u8],
        remaining: Duration,
    ) -> Result<Vec<u8>, ErrorCategory> {
        let admitted = program(HookHandlerKind::Wasm, module);
        let handlers = handlers_with(admitted.clone()).with_wasm_runtime(Arc::clone(runtime));
        bound(&handlers, &admitted).run_blocking(&envelope(), remaining)
    }

    fn hex_escape(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
    }

    /// A guest whose answer window holds `document` verbatim.
    fn answer_guest(document: &str) -> Vec<u8> {
        let document = document.as_bytes();
        wat::parse_str(format!(
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
        ))
        .expect("guest wat compiles")
    }

    /// A guest that answers with `answer_len` bytes from a memory big enough
    /// to hold them. The request lands in the first page and the answer
    /// starts at the second, so neither window overlaps the other.
    fn sized_answer_guest(answer_len: usize) -> Vec<u8> {
        const ANSWER_PTR: usize = 65_536;
        let pages = (ANSWER_PTR + answer_len).div_ceil(65_536);
        wat::parse_str(format!(
            r#"(module
  (memory (export "memory") {pages})
  (func (export "alloc") (param $len i32) (result i32) (i32.const 1024))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const {ANSWER_PTR}))
  (func (export "result_len") (result i32) (i32.const {answer_len}))
)"#
        ))
        .expect("guest wat compiles")
    }

    /// A guest that answers normally from a memory of exactly `pages` pages.
    fn sized_memory_guest(pages: usize) -> Vec<u8> {
        let document = br#"{"answer":"none"}"#;
        wat::parse_str(format!(
            r#"(module
  (memory (export "memory") {pages})
  (data (i32.const 1024) "{escaped}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const {len}))
)"#,
            escaped = hex_escape(document),
            len = document.len(),
        ))
        .expect("guest wat compiles")
    }

    /// A guest that never returns.
    fn spinning_guest() -> Vec<u8> {
        wat::parse_str(
            r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32)
    (loop $forever (br $forever))
    (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const 0))
)"#,
        )
        .expect("guest wat compiles")
    }

    /// Unsigned LEB128, for the padding section below.
    fn leb128(mut value: usize) -> Vec<u8> {
        let mut encoded = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                encoded.push(byte);
                return encoded;
            }
            encoded.push(byte | 0x80);
        }
    }

    /// A structurally valid module of exactly `len` bytes: the guest plus one
    /// trailing custom section, which every conforming consumer ignores.
    fn module_padded_to(len: usize, guest: &[u8]) -> Vec<u8> {
        let mut bytes = guest.to_vec();
        assert!(bytes.len() < len, "the guest already exceeds {len}");
        for header_len in 1..=5 {
            let payload_len = len - bytes.len() - 1 - header_len;
            if leb128(payload_len).len() == header_len {
                bytes.push(0x00);
                bytes.extend(leb128(payload_len));
                bytes.extend(leb128(1));
                bytes.push(b'p');
                bytes.resize(len, 0);
                return bytes;
            }
        }
        panic!("no LEB128 header length fits {len}");
    }

    #[test]
    fn a_wasm_handler_answers_with_the_bytes_its_module_writes() {
        let runtime = runtime(DEFAULT_BUDGETS);
        let answer = run_wasm(
            &runtime,
            &answer_guest(r#"{"answer":"none"}"#),
            Duration::from_secs(5),
        )
        .expect("the reviewed module answers");
        assert_eq!(br#"{"answer":"none"}"#.as_slice(), answer.as_slice());
    }

    #[test]
    fn a_wasm_handler_without_a_runtime_is_an_execution_refusal() {
        let module = answer_guest(r#"{"answer":"none"}"#);
        let admitted = program(HookHandlerKind::Wasm, &module);
        let handlers = handlers_with(admitted.clone());
        assert_eq!(
            Err(ErrorCategory::Execution),
            bound(&handlers, &admitted).run_blocking(&envelope(), Duration::from_secs(5))
        );
    }

    #[test]
    fn a_module_is_prepared_once_and_reused_by_content_identity() {
        let runtime = runtime(DEFAULT_BUDGETS);
        let module = answer_guest(r#"{"answer":"none"}"#);
        for _ in 0..3 {
            run_wasm(&runtime, &module, Duration::from_secs(5)).expect("the module answers");
        }
        assert_eq!(1, runtime.preparation_count());
    }

    /// The module ceiling, at the byte.
    #[test]
    fn the_wasm_module_ceiling_admits_a_module_at_the_bound_and_refuses_one_byte_more() {
        let guest = answer_guest(r#"{"answer":"none"}"#);
        let ceiling = 65_536;
        let runtime = runtime(WasmHookBudgets {
            max_module_bytes: ceiling,
            ..DEFAULT_BUDGETS
        });
        assert!(
            run_wasm(
                &runtime,
                &module_padded_to(ceiling, &guest),
                Duration::from_secs(5)
            )
            .is_ok(),
            "a module at the ceiling is admitted"
        );
        assert_eq!(
            Err(ErrorCategory::Resource),
            run_wasm(
                &runtime,
                &module_padded_to(ceiling + 1, &guest),
                Duration::from_secs(5)
            )
        );
    }

    /// The guest-memory ceiling, at the page. The same module is admitted
    /// under a ceiling that covers its declared memory and refused under one
    /// a single page short of it.
    #[test]
    fn the_wasm_guest_memory_ceiling_admits_a_module_at_the_bound_and_refuses_one_page_more() {
        const PAGE: usize = 65_536;
        const PAGES: usize = 4;
        let guest = sized_memory_guest(PAGES);
        let admitting = runtime(WasmHookBudgets {
            max_guest_memory_bytes: PAGES * PAGE,
            ..DEFAULT_BUDGETS
        });
        assert!(
            run_wasm(&admitting, &guest, Duration::from_secs(5)).is_ok(),
            "a memory at the ceiling is admitted"
        );
        let refusing = runtime(WasmHookBudgets {
            max_guest_memory_bytes: (PAGES - 1) * PAGE,
            ..DEFAULT_BUDGETS
        });
        assert_eq!(
            Err(ErrorCategory::Resource),
            run_wasm(&refusing, &guest, Duration::from_secs(5))
        );
    }

    /// The answer ceiling, at the byte.
    #[test]
    fn the_wasm_answer_ceiling_admits_the_largest_answer_and_refuses_one_byte_more() {
        let runtime = runtime(DEFAULT_BUDGETS);
        assert_eq!(
            MAX_OUTPUT_BYTES,
            run_wasm(
                &runtime,
                &sized_answer_guest(MAX_OUTPUT_BYTES),
                Duration::from_secs(10)
            )
            .expect("an answer at the ceiling is admitted")
            .len()
        );
        assert_eq!(
            Err(ErrorCategory::Resource),
            run_wasm(
                &runtime,
                &sized_answer_guest(MAX_OUTPUT_BYTES + 1),
                Duration::from_secs(10)
            )
        );
    }

    /// The attempt timeout, flipped around a returning and a spinning guest.
    #[test]
    fn the_wasm_attempt_timeout_admits_a_module_inside_it_and_refuses_one_that_outruns_it() {
        let runtime = runtime(DEFAULT_BUDGETS);
        assert!(
            run_wasm(
                &runtime,
                &answer_guest(r#"{"answer":"none"}"#),
                Duration::from_secs(10)
            )
            .is_ok(),
            "a module that returns stays inside"
        );
        assert_eq!(
            Err(ErrorCategory::Deadline),
            run_wasm(&runtime, &spinning_guest(), Duration::from_millis(50))
        );
    }

    #[test]
    fn a_module_that_does_not_parse_is_a_source_refusal() {
        let runtime = runtime(DEFAULT_BUDGETS);
        assert_eq!(
            Err(ErrorCategory::Source),
            run_wasm(&runtime, b"not a module", Duration::from_secs(5))
        );
    }
}
