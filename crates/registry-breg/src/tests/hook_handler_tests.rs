// SPDX-License-Identifier: Apache-2.0
//! The local hook handler seam: identity binding, the envelope the entry
//! point receives, the canonical answer, and one flip test for every budget
//! that bounds a local run.
//!
//! A flip test pins a budget by proving both sides of it: the largest input
//! the budget admits is accepted, and the next one up is refused with the
//! category the shared error table assigns.

use std::time::Duration;

use registry_platform_hooks::delivery::{HookHandler, HookHandlerBinding};
use registry_platform_hooks::{ErrorCategory, HookHandlerKind, HookMessage, MAX_OUTPUT_BYTES};
use serde_json::{json, Value};

use super::{encode_rhai_answer, run_program, verified_digest, HookHandlerRegistry, HookProgram};
use crate::compiler::{compile_project_with_assets, CompileProfile, WEBHOOK_ATTEMPT_TIMEOUT_MS};
use crate::contract::{parse_project_json, ModuleAssetSource};
use crate::model::{CompiledHookHandler, CompiledHookHandlerKind, CompiledRegistry};

const PACKAGE_REVISION: &str = "hook-handler-tests";

/// A registry project whose one entity declares one `after` hook bound to the
/// local program at `path`.
fn project_with_local_hook(kind: &str, path: &str) -> Value {
    let handler = match kind {
        "rhai" => json!({"kind": "rhai", "script": path, "abi": "registry.hook-handler/v1"}),
        "wasm" => json!({"kind": "wasm", "module": path, "abi": "registry.hook-handler/v1"}),
        other => panic!("unknown local handler kind {other}"),
    };
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "hook-handler", "version": "1", "defaultLanguage": "en",
                     "canonicalBaseIri": "https://hook-handler.example.test"},
        "entities": [{
            "id": "case",
            "primaryDataset": "test-dataset",
            "route": "cases",
            "mutationMode": "mutable",
            "tombstone": true,
            "classification": "internal",
            "fields": [
                {"id": "label", "type": "string", "maxLength": 64, "classification": "public"}
            ],
            "hooks": [{
                "id": "case-created",
                "phase": "after",
                "trigger": "created",
                "projection": ["label"],
                "handler": handler
            }]
        }]
    })
}

fn compile_local_hook(kind: &str, path: &str, bytes: &[u8]) -> CompiledRegistry {
    let source = project_with_local_hook(kind, path);
    let project = parse_project_json(&serde_json::to_vec(&source).expect("project serializes"))
        .expect("project parses");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: path.to_owned(),
            bytes: bytes.to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("a local hook handler compiles")
}

fn rhai_program(source: &str) -> HookProgram {
    HookProgram {
        kind: CompiledHookHandlerKind::Rhai,
        digest: "sha256:0".to_owned(),
        bytes: source.as_bytes().to_vec(),
        attempt_timeout: Duration::from_millis(u64::from(WEBHOOK_ATTEMPT_TIMEOUT_MS)),
        maximum_attempts: 1,
    }
}

/// The captured envelope shape a hook delivery carries, reduced to the members
/// these tests read. The worker hands the bytes through unchanged.
fn envelope() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "specversion": "1.0",
        "id": "0192f0d6-1b8c-7c2f-9f47-9f5a0f2a4b1c",
        "type": "case.created",
        "data": {"label": "north"}
    }))
    .expect("envelope serializes")
}

#[test]
fn a_rhai_handler_answers_with_canonical_message_bytes() {
    let program = rhai_program(r#"fn handle(ctx) { #{"answer": "none"} }"#);
    let answer = run_program(&program, &envelope(), Duration::from_secs(5))
        .expect("the reviewed script answers");
    assert_eq!(br#"{"answer":"none"}"#.as_slice(), answer.as_slice());
    assert_eq!(
        HookMessage::Nothing,
        HookMessage::from_canonical_json(&answer, &Default::default())
            .expect("the answer is the shared handler message")
    );
}

#[test]
fn a_rhai_handler_reads_the_envelope_as_its_one_argument() {
    // The script answers only when the envelope member it projects is the one
    // the capture wrote, which is what proves the envelope arrives whole.
    let program = rhai_program(
        r#"fn handle(ctx) {
             if ctx["data"]["label"] == "north" { #{"answer": "none"} } else { () }
           }"#,
    );
    let answer = run_program(&program, &envelope(), Duration::from_secs(5))
        .expect("the reviewed script answers");
    assert_eq!(br#"{"answer":"none"}"#.as_slice(), answer.as_slice());
}

#[test]
fn a_rhai_handler_that_returns_nothing_answers_empty() {
    let program = rhai_program("fn handle(ctx) { () }");
    let answer = run_program(&program, &envelope(), Duration::from_secs(5))
        .expect("the reviewed script answers");
    assert!(answer.is_empty(), "an absent answer carries no bytes");
}

#[test]
fn a_script_without_the_entry_point_is_a_source_refusal() {
    let program = rhai_program("fn other(ctx) { () }");
    assert_eq!(
        ErrorCategory::Source,
        run_program(&program, &envelope(), Duration::from_secs(5))
            .expect_err("a script without handle is refused")
            .category
    );
}

#[test]
fn a_script_that_fails_is_an_execution_refusal() {
    let program = rhai_program(r#"fn handle(ctx) { throw "no" }"#);
    assert_eq!(
        ErrorCategory::Execution,
        run_program(&program, &envelope(), Duration::from_secs(5))
            .expect_err("a throwing script is refused")
            .category
    );
}

// ---------------------------------------------------------------------------
// Budget flip tests: rhai
// ---------------------------------------------------------------------------

/// The answer ceiling, at the byte. The value is built directly rather than
/// returned by a script, because the script data budgets sit far below this
/// ceiling and would refuse the oversized case for the wrong reason.
#[test]
fn the_rhai_answer_ceiling_admits_the_largest_answer_and_refuses_one_byte_more() {
    // `{"answer":"refusal","refusal":{"code":"<padding>"}}` canonicalizes to a
    // fixed frame plus the padding, so the padding length sets the exact size.
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
            Some(category) => assert_eq!(
                category,
                encoded
                    .expect_err("an answer over the ceiling is refused")
                    .category
            ),
        }
    }
}

/// The attempt timeout, flipped around the same script.
#[test]
fn the_rhai_attempt_timeout_admits_a_script_inside_it_and_refuses_one_that_outruns_it() {
    // The loop stays well inside the fixed operation budget, so the only
    // difference between the two runs below is the attempt timeout.
    let program = rhai_program(
        r#"fn handle(ctx) {
             let total = 0;
             for i in 0..8000 { total += i; }
             #{"answer": "none"}
           }"#,
    );
    assert!(
        run_program(&program, &envelope(), Duration::from_secs(30)).is_ok(),
        "the script finishes inside a generous budget"
    );
    assert_eq!(
        ErrorCategory::Deadline,
        run_program(&program, &envelope(), Duration::from_millis(1))
            .expect_err("the same script outruns a one millisecond budget")
            .category
    );
}

/// The Rhai operation budget, flipped around the loop bound that crosses it.
/// The budget is a fixed profile constant, not operator configuration.
#[test]
fn the_rhai_operation_budget_admits_a_bounded_loop_and_refuses_a_runaway_one() {
    let bounded = rhai_program(
        r#"fn handle(ctx) {
             let total = 0;
             for i in 0..1000 { total += i; }
             #{"answer": "none"}
           }"#,
    );
    assert!(
        run_program(&bounded, &envelope(), Duration::from_secs(30)).is_ok(),
        "a bounded loop stays inside the operation budget"
    );
    let runaway = rhai_program(
        r#"fn handle(ctx) {
             let total = 0;
             loop { total += 1; }
           }"#,
    );
    assert_eq!(
        ErrorCategory::Resource,
        run_program(&runaway, &envelope(), Duration::from_secs(30))
            .expect_err("an unbounded loop exhausts the operation budget")
            .category
    );
}

/// The envelope conversion budgets, flipped around the map-entry bound. The
/// conversion is the same bounded reader the change-request planner uses.
#[test]
fn the_rhai_envelope_bounds_admit_the_widest_object_and_refuse_one_member_more() {
    for (members, expected) in [
        (crate::rhai_planner::MAXIMUM_MAP_ENTRIES, None),
        (
            crate::rhai_planner::MAXIMUM_MAP_ENTRIES + 1,
            Some(ErrorCategory::Resource),
        ),
    ] {
        let data: serde_json::Map<String, Value> = (0..members)
            .map(|index| (format!("f{index}"), Value::from(index as i64)))
            .collect();
        let envelope = serde_json::to_vec(&json!({"data": data})).expect("envelope serializes");
        let program = rhai_program(r#"fn handle(ctx) { #{"answer": "none"} }"#);
        let outcome = run_program(&program, &envelope, Duration::from_secs(30));
        match expected {
            None => assert!(outcome.is_ok(), "an object at the bound is converted"),
            Some(category) => assert_eq!(
                category,
                outcome
                    .expect_err("an object over the bound is refused")
                    .category
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Identity binding
// ---------------------------------------------------------------------------

const NONE_ANSWER_SCRIPT: &str = r#"fn handle(ctx) { #{"answer": "none"} }"#;

fn rhai_registry() -> (CompiledRegistry, String, String) {
    let compiled = compile_local_hook("rhai", "hooks/case.rhai", NONE_ANSWER_SCRIPT.as_bytes());
    let delivery = &compiled.event_deliveries().deliveries[0];
    let id = delivery.id.clone();
    let digest = delivery
        .handler_digest()
        .expect("a local delivery carries its handler digest")
        .to_owned();
    (compiled, id, digest)
}

#[test]
fn a_local_delivery_binds_to_its_reviewed_program() {
    let (compiled, id, digest) = rhai_registry();
    let registry = HookHandlerRegistry::new(&compiled, PACKAGE_REVISION);
    let handler = registry
        .handler(HookHandlerBinding {
            kind: HookHandlerKind::Rhai,
            compiled_delivery_id: &id,
            package_revision: PACKAGE_REVISION,
            handler_digest: &digest,
        })
        .expect("the running package holds the bound program");
    assert_eq!(digest, handler.handler_digest());
    assert_eq!(
        Duration::from_millis(u64::from(WEBHOOK_ATTEMPT_TIMEOUT_MS)),
        handler.attempt_timeout()
    );
}

#[test]
fn a_delivery_from_another_package_revision_binds_to_nothing() {
    let (compiled, id, digest) = rhai_registry();
    let registry = HookHandlerRegistry::new(&compiled, PACKAGE_REVISION);
    assert!(registry
        .handler(HookHandlerBinding {
            kind: HookHandlerKind::Rhai,
            compiled_delivery_id: &id,
            package_revision: "some-other-revision",
            handler_digest: &digest,
        })
        .is_none());
}

#[test]
fn a_delivery_naming_another_program_digest_binds_to_nothing() {
    let (compiled, id, _) = rhai_registry();
    let registry = HookHandlerRegistry::new(&compiled, PACKAGE_REVISION);
    assert!(registry
        .handler(HookHandlerBinding {
            kind: HookHandlerKind::Rhai,
            compiled_delivery_id: &id,
            package_revision: PACKAGE_REVISION,
            handler_digest: &format!("sha256:{}", "0".repeat(64)),
        })
        .is_none());
}

#[test]
fn a_delivery_naming_another_handler_kind_binds_to_nothing() {
    let (compiled, id, digest) = rhai_registry();
    let registry = HookHandlerRegistry::new(&compiled, PACKAGE_REVISION);
    assert!(registry
        .handler(HookHandlerBinding {
            kind: HookHandlerKind::Wasm,
            compiled_delivery_id: &id,
            package_revision: PACKAGE_REVISION,
            handler_digest: &digest,
        })
        .is_none());
}

#[test]
fn a_program_whose_recorded_digest_does_not_cover_its_bytes_is_never_admitted() {
    let mut handler = CompiledHookHandler {
        kind: CompiledHookHandlerKind::Rhai,
        abi: registry_platform_hooks::HOOK_HANDLER_ABI_V1.to_owned(),
        source_module: None,
        source_path: "hooks/case.rhai".to_owned(),
        digest: String::new(),
        bytes: NONE_ANSWER_SCRIPT.as_bytes().to_vec(),
    };
    let (_, _, digest) = rhai_registry();
    handler.digest.clone_from(&digest);
    assert_eq!(Some(digest), verified_digest(&handler));

    // The same recorded digest over different bytes is never admitted, so a
    // substituted program cannot inherit another program's retained rows.
    handler.bytes = b"fn handle(ctx) { () }".to_vec();
    assert_eq!(None, verified_digest(&handler));
}

#[test]
fn a_program_speaking_another_handler_abi_is_never_admitted() {
    let (_, _, digest) = rhai_registry();
    let handler = CompiledHookHandler {
        kind: CompiledHookHandlerKind::Rhai,
        abi: "registry.hook-handler/v2".to_owned(),
        source_module: None,
        source_path: "hooks/case.rhai".to_owned(),
        digest,
        bytes: NONE_ANSWER_SCRIPT.as_bytes().to_vec(),
    };
    assert_eq!(None, verified_digest(&handler));
}

// ---------------------------------------------------------------------------
// Budget flip tests: wasm
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm")]
mod wasm {
    use super::{envelope, run_program, HookProgram};
    use crate::model::CompiledHookHandlerKind;
    use crate::wasm_runtime::{install, shutdown, WasmExecutionBudgets};
    use registry_platform_hooks::{ErrorCategory, MAX_OUTPUT_BYTES};
    use registry_platform_script::wasm::Backend;
    use std::time::Duration;

    /// The WASM runtime is installed process wide, so the tests that install
    /// their own budgets take turns. A failing test poisons the lock without
    /// leaving shared state behind, so the next one recovers it rather than
    /// reporting the first failure a second time.
    static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn default_backend() -> Backend {
        crate::wasm_handler::execution_backend(crate::wasm_handler::WasmExecutionBackend::default())
    }

    fn hex_escape(bytes: &[u8]) -> String {
        let mut escaped = String::with_capacity(bytes.len() * 4);
        for byte in bytes {
            escaped.push_str(&format!("\\{byte:02x}"));
        }
        escaped
    }

    /// The digest is the module's own content hash, as the compiler records
    /// it: the prepared-module cache is keyed by that identity, so two guests
    /// sharing a digest would share a compilation.
    fn wasm_program(module: Vec<u8>) -> HookProgram {
        use sha2::{Digest, Sha256};
        let digest = format!(
            "sha256:{}",
            crate::immediate_actions::hex_lower(&Sha256::digest(&module))
        );
        HookProgram {
            kind: CompiledHookHandlerKind::Wasm,
            digest,
            bytes: module,
            attempt_timeout: Duration::from_secs(5),
            maximum_attempts: 1,
        }
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
    /// to hold them, used to flip the answer ceiling. The request lands in the
    /// first page and the answer starts at the second, so neither window
    /// overlaps the other.
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

    /// A guest that answers normally from a memory of exactly `pages` pages,
    /// used to flip the guest-memory ceiling.
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

    /// A guest that never returns, used to flip the attempt timeout.
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

    fn install_budgets(budgets: WasmExecutionBudgets) {
        install(budgets, default_backend(), 4).expect("the runtime installs");
    }

    #[test]
    fn a_wasm_handler_answers_with_the_bytes_its_module_writes() {
        let _guard = INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        install_budgets(WasmExecutionBudgets::default());
        let program = wasm_program(answer_guest(r#"{"answer":"none"}"#));
        let answer = run_program(&program, &envelope(), Duration::from_secs(5))
            .expect("the reviewed module answers");
        shutdown();
        assert_eq!(br#"{"answer":"none"}"#.as_slice(), answer.as_slice());
    }

    #[test]
    fn a_wasm_handler_without_an_installed_runtime_is_an_execution_refusal() {
        let _guard = INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        shutdown();
        let program = wasm_program(answer_guest(r#"{"answer":"none"}"#));
        assert_eq!(
            ErrorCategory::Execution,
            run_program(&program, &envelope(), Duration::from_secs(5))
                .expect_err("evaluation before any install is refused")
                .category
        );
    }

    /// The operator-configurable module ceiling, at the byte.
    #[test]
    fn the_wasm_module_ceiling_admits_a_module_at_the_bound_and_refuses_one_byte_more() {
        let _guard = INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let guest = answer_guest(r#"{"answer":"none"}"#);
        let ceiling = WasmExecutionBudgets::DEFAULT_MAX_MODULE_BYTES.min(65_536);
        install_budgets(WasmExecutionBudgets {
            max_module_bytes: ceiling,
            ..WasmExecutionBudgets::default()
        });
        let at_bound = wasm_program(module_padded_to(ceiling, &guest));
        let over_bound = wasm_program(module_padded_to(ceiling + 1, &guest));
        let admitted = run_program(&at_bound, &envelope(), Duration::from_secs(5));
        let refused = run_program(&over_bound, &envelope(), Duration::from_secs(5));
        shutdown();
        assert!(admitted.is_ok(), "a module at the ceiling is admitted");
        assert_eq!(
            ErrorCategory::Resource,
            refused
                .expect_err("a module over the ceiling is refused")
                .category
        );
    }

    /// The operator-configurable guest-memory ceiling, at the page. The same
    /// module is admitted under a ceiling that covers its declared memory and
    /// refused under one a single page short of it.
    #[test]
    fn the_wasm_guest_memory_ceiling_admits_a_module_at_the_bound_and_refuses_one_page_more() {
        let _guard = INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        const PAGE: usize = 65_536;
        const PAGES: usize = 4;
        let guest = sized_memory_guest(PAGES);
        install_budgets(WasmExecutionBudgets {
            max_guest_memory_bytes: PAGES * PAGE,
            ..WasmExecutionBudgets::default()
        });
        let admitted = run_program(
            &wasm_program(guest.clone()),
            &envelope(),
            Duration::from_secs(5),
        );
        shutdown();
        assert!(admitted.is_ok(), "a memory at the ceiling is admitted");

        install_budgets(WasmExecutionBudgets {
            max_guest_memory_bytes: (PAGES - 1) * PAGE,
            ..WasmExecutionBudgets::default()
        });
        let refused = run_program(&wasm_program(guest), &envelope(), Duration::from_secs(5));
        shutdown();
        assert_eq!(
            ErrorCategory::Resource,
            refused
                .expect_err("a memory over the ceiling is refused")
                .category
        );
    }

    /// The answer ceiling, at the byte.
    #[test]
    fn the_wasm_answer_ceiling_admits_the_largest_answer_and_refuses_one_byte_more() {
        let _guard = INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        install_budgets(WasmExecutionBudgets::default());
        let admitted = run_program(
            &wasm_program(sized_answer_guest(MAX_OUTPUT_BYTES)),
            &envelope(),
            Duration::from_secs(10),
        );
        let refused = run_program(
            &wasm_program(sized_answer_guest(MAX_OUTPUT_BYTES + 1)),
            &envelope(),
            Duration::from_secs(10),
        );
        shutdown();
        assert_eq!(
            MAX_OUTPUT_BYTES,
            admitted
                .expect("an answer at the ceiling is admitted")
                .len()
        );
        assert_eq!(
            ErrorCategory::Resource,
            refused
                .expect_err("an answer over the ceiling is refused")
                .category
        );
    }

    /// The attempt timeout, flipped around the same spinning guest.
    #[test]
    fn the_wasm_attempt_timeout_admits_a_module_inside_it_and_refuses_one_that_outruns_it() {
        let _guard = INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        install_budgets(WasmExecutionBudgets::default());
        let admitted = run_program(
            &wasm_program(answer_guest(r#"{"answer":"none"}"#)),
            &envelope(),
            Duration::from_secs(10),
        );
        let refused = run_program(
            &wasm_program(spinning_guest()),
            &envelope(),
            Duration::from_millis(50),
        );
        shutdown();
        assert!(admitted.is_ok(), "a module that returns stays inside");
        assert_eq!(
            ErrorCategory::Deadline,
            refused
                .expect_err("a module that never returns outruns the budget")
                .category
        );
    }
}
