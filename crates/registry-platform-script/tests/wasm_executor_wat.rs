// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the WASM executor, written against inline wat
//! modules that implement (or deliberately break) the guest byte ABI.
//!
//! `Module::new` accepts wat text because the wasmtime `wat` feature is on by
//! default; the `wat_text_is_accepted` test pins that fact (a binary-only
//! decoder would reject these strings before export validation could run).
#![cfg(feature = "wasm")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use registry_platform_script::wasm::{Backend, Budgets, EpochTicker, Executor, InvokeError};

const MIB: usize = 1024 * 1024;

/// A wat guest implementing the byte ABI with a bump allocator. The `handle`
/// and `result_len` bodies are injected per test. The result window lives at
/// fixed offset 1024 and the heap starts after it at 4096.
fn guest_wat(handle_body: &str, result_len_body: &str) -> String {
    format!(
        r#"(module
  (memory (export "memory") 1)
  (global $out_len (mut i32) (i32.const 0))
  (global $heap (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $ptr))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32)
    {handle_body})
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) {result_len_body})
)"#
    )
}

/// `handle` copies the request bytes into the result window; `result_len`
/// reports the stored length, so a correct roundtrip echoes the input.
const ECHO_HANDLE: &str = r#"(memory.copy (i32.const 1024) (local.get $ptr) (local.get $len))
    (global.set $out_len (local.get $len))
    (i32.const 0)"#;
const ECHO_LEN: &str = "(global.get $out_len)";

/// `handle` spins forever while burning fuel (the arithmetic keeps the loop
/// off wasmtime's zero-fuel instruction set).
const SPIN_HANDLE: &str = r#"(local $i i32)
    (loop $spin
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $spin))
    (i32.const 0)"#;

fn budgets(tune: impl FnOnce(&mut Budgets)) -> Budgets {
    let mut budgets = Budgets::default();
    tune(&mut budgets);
    budgets
}

fn executor(backend: Backend) -> Executor {
    Executor::new(backend, Budgets::default()).expect("fixed engine config is valid")
}

fn backends() -> [Backend; 2] {
    [Backend::Native, Backend::Pulley]
}

fn err_of<T>(result: Result<T, InvokeError>) -> InvokeError {
    match result {
        Ok(_) => panic!("expected an error, got a success"),
        Err(err) => err,
    }
}

#[test]
fn wat_text_is_accepted() {
    // "(module)" is valid wat and an invalid binary; reaching export
    // validation (MissingExport) proves the text path compiled it.
    let err = err_of(executor(Backend::Native).prepare(b"(module)"));
    assert!(matches!(err, InvokeError::MissingExport { .. }), "{err}");
}

#[test]
fn happy_path_roundtrip_and_stats() {
    for backend in backends() {
        let exec = executor(backend);
        let prepared = exec
            .prepare(guest_wat(ECHO_HANDLE, ECHO_LEN).as_bytes())
            .expect("wat guest passes validation");
        let ok = exec.invoke(&prepared, b"hello registry").expect("echo");
        assert_eq!(ok.output, b"hello registry");
        assert!(ok.stats.fuel_consumed > 0);
        assert_eq!(ok.stats.memory_bytes, 64 * 1024);
        assert!(!ok.stats.memory_growth_denied);
    }
}

#[test]
fn fuel_exhaustion() {
    for backend in backends() {
        let exec = Executor::new(backend, budgets(|b| b.fuel = 5_000))
            .expect("fixed engine config is valid");
        let prepared = exec
            .prepare(guest_wat(SPIN_HANDLE, "(i32.const 0)").as_bytes())
            .expect("wat guest passes validation");
        let err = err_of(exec.invoke(&prepared, b"x"));
        assert!(matches!(err, InvokeError::FuelExhausted), "{err}");
    }
}

#[test]
fn epoch_deadline_with_host_driven_ticks() {
    // Deterministic deadline: the test thread, not a timer, drives the ticks
    // while the guest spins on another thread.
    let exec = Executor::new(Backend::Native, budgets(|b| b.epoch_deadline_ticks = 3))
        .expect("fixed engine config is valid");
    let prepared = exec
        .prepare(guest_wat(SPIN_HANDLE, "(i32.const 0)").as_bytes())
        .expect("wat guest passes validation");

    let done = AtomicBool::new(false);
    let outcome = thread::scope(|scope| {
        let worker = {
            let exec = &exec;
            let prepared = &prepared;
            let done = &done;
            scope.spawn(move || {
                let outcome = exec.invoke(prepared, b"x");
                done.store(true, Ordering::Release);
                outcome
            })
        };
        // ~200us per tick; the 50_000-iteration cap is a 10s failure guard.
        for _ in 0..50_000 {
            if done.load(Ordering::Acquire) {
                break;
            }
            exec.engine().increment_epoch();
            thread::sleep(Duration::from_micros(200));
        }
        worker.join().expect("invoke thread panicked")
    });
    assert!(matches!(err_of(outcome), InvokeError::DeadlineExceeded));
}

#[test]
fn epoch_deadline_with_ticker() {
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(guest_wat(SPIN_HANDLE, "(i32.const 0)").as_bytes())
        .expect("wat guest passes validation");
    let ticker = EpochTicker::spawn(exec.engine().clone(), Duration::from_millis(1));
    let err = err_of(exec.invoke(&prepared, b"x"));
    ticker.stop();
    assert!(matches!(err, InvokeError::DeadlineExceeded), "{err}");
}

#[test]
fn ticker_stop_joins_and_double_stop_is_harmless() {
    let exec = executor(Backend::Native);
    let ticker = EpochTicker::spawn(exec.engine().clone(), Duration::from_millis(1));
    thread::sleep(Duration::from_millis(5));
    // stop() joins the ticker thread, so returning proves the thread ended.
    ticker.stop();
    ticker.stop();
}

#[test]
fn huge_initial_memory_is_denied() {
    // 600 pages = 39 MiB > the 32 MiB guest-memory ceiling; the limiter is
    // attached before instantiation, so creation itself fails.
    let wat = guest_wat("(i32.const 0)", "(i32.const 0)").replacen(
        "(memory (export \"memory\") 1)",
        "(memory (export \"memory\") 600)",
        1,
    );
    let exec = executor(Backend::Native);
    let prepared = exec.prepare(wat.as_bytes()).expect("exports are valid");
    match err_of(exec.invoke(&prepared, b"x")) {
        InvokeError::MemoryLimitExceeded { requested, max } => {
            assert_eq!(requested, 600 * 64 * 1024);
            assert_eq!(max, 32 * MIB);
        }
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn growth_denial_is_recorded_and_guest_visible() {
    // handle grows 64 pages at a time until memory.grow returns -1, then
    // reports '1' in the result window: the denial is guest-visible and the
    // call still completes without a trap.
    let handle = r#"(block $denied
    (loop $grow
      (br_if $denied (i32.eq (memory.grow (i32.const 64)) (i32.const -1)))
      (br $grow)))
  (i32.store8 (i32.const 1024) (i32.const 49))
  (i32.const 0)"#;
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(guest_wat(handle, "(i32.const 1)").as_bytes())
        .expect("wat guest passes validation");
    let ok = exec.invoke(&prepared, b"x").expect("denial is not a trap");
    assert_eq!(ok.output, b"1");
    assert!(ok.stats.memory_growth_denied);
    assert!(ok.stats.memory_bytes > 64 * 1024);
    assert!(ok.stats.memory_bytes <= (32 * MIB) as u64);
}

#[test]
fn oversized_output_is_rejected_before_allocation() {
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(guest_wat("(i32.const 0)", "(i32.const 999_999_999)").as_bytes())
        .expect("wat guest passes validation");
    match err_of(exec.invoke(&prepared, b"x")) {
        InvokeError::OutputTooLarge { len, max } => {
            assert_eq!(len, 999_999_999);
            assert_eq!(max, MIB);
        }
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn alloc_returning_zero_is_rejected() {
    let wat = guest_wat("(i32.const 0)", "(i32.const 0)").replacen(
        "(local.get $ptr))",
        "(i32.const 0))",
        1,
    );
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(wat.as_bytes())
        .expect("wat guest passes validation");
    let err = err_of(exec.invoke(&prepared, b"payload"));
    assert!(
        matches!(err, InvokeError::AllocInvalidPointer { .. }),
        "{err}"
    );
}

#[test]
fn alloc_returning_out_of_bounds_pointer_is_rejected() {
    let wat = guest_wat("(i32.const 0)", "(i32.const 0)").replacen(
        "(local.get $ptr))",
        "(i32.const 0x7fff0000))",
        1,
    );
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(wat.as_bytes())
        .expect("wat guest passes validation");
    let err = err_of(exec.invoke(&prepared, b"payload"));
    assert!(
        matches!(err, InvokeError::AllocInvalidPointer { .. }),
        "{err}"
    );
}

#[test]
fn imports_are_rejected() {
    let wat = guest_wat("(i32.const 0)", "(i32.const 0)").replacen(
        "(module\n",
        "(module\n  (import \"env\" \"log\" (func $log (param i32)))\n",
        1,
    );
    let exec = executor(Backend::Native);
    match err_of(exec.prepare(wat.as_bytes())) {
        InvokeError::UnsupportedImport { module, name } => {
            assert_eq!(module.as_str(), "env");
            assert_eq!(name.as_str(), "log");
        }
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn missing_export_is_rejected() {
    let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 0))
)"#;
    let exec = executor(Backend::Native);
    match err_of(exec.prepare(wat.as_bytes())) {
        InvokeError::MissingExport { name } => assert_eq!(name, "result_len"),
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn wrong_signature_is_rejected() {
    let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i64) (result i32) (i32.const 0))
  (func (export "handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 0))
  (func (export "result_len") (result i32) (i32.const 0))
)"#;
    let exec = executor(Backend::Native);
    match err_of(exec.prepare(wat.as_bytes())) {
        InvokeError::ExportTypeMismatch { name } => assert_eq!(name, "alloc"),
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn wrong_export_kind_is_rejected() {
    let wat = r#"(module
  (global (export "memory") i32 (i32.const 0))
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 0))
  (func (export "result_len") (result i32) (i32.const 0))
)"#;
    let exec = executor(Backend::Native);
    match err_of(exec.prepare(wat.as_bytes())) {
        InvokeError::ExportTypeMismatch { name } => assert_eq!(name, "memory"),
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn unknown_extra_export_is_rejected() {
    // Insert an extra export just before the module's closing paren.
    let base = guest_wat("(i32.const 0)", "(i32.const 0)");
    let wat = format!("{}  (func (export \"extra\"))\n)", &base[..base.len() - 1]);
    let exec = executor(Backend::Native);
    match err_of(exec.prepare(wat.as_bytes())) {
        InvokeError::UnexpectedExport { name } => assert_eq!(name.as_str(), "extra"),
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn optional_init_export_is_accepted() {
    let wat = guest_wat("(i32.const 0)", "(i32.const 0)").replace(
        "(func (export \"result_len\")",
        "(func (export \"init\"))\n  (func (export \"result_len\")",
    );
    let exec = executor(Backend::Native);
    assert!(exec.prepare(wat.as_bytes()).is_ok());
}

#[test]
fn init_export_with_wrong_signature_is_rejected() {
    let wat = guest_wat("(i32.const 0)", "(i32.const 0)").replace(
        "(func (export \"result_len\")",
        "(func (export \"init\") (param i32))\n  (func (export \"result_len\")",
    );
    let exec = executor(Backend::Native);
    match err_of(exec.prepare(wat.as_bytes())) {
        InvokeError::ExportTypeMismatch { name } => assert_eq!(name, "init"),
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn oversized_module_is_rejected_before_compiling() {
    let exec = Executor::new(Backend::Native, budgets(|b| b.max_module_bytes = 8))
        .expect("fixed engine config is valid");
    let bytes = guest_wat("(i32.const 0)", "(i32.const 0)");
    match err_of(exec.prepare(bytes.as_bytes())) {
        InvokeError::ModuleTooLarge { size, max } => {
            assert_eq!(max, 8);
            assert_eq!(size, bytes.len());
        }
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn shared_memory_fails_validation() {
    let wat = guest_wat("(i32.const 0)", "(i32.const 0)").replacen(
        "(memory (export \"memory\") 1)",
        "(memory (export \"memory\") 1 1 shared)",
        1,
    );
    let exec = executor(Backend::Native);
    let err = err_of(exec.prepare(wat.as_bytes()));
    assert!(matches!(err, InvokeError::InvalidModule { .. }), "{err}");
}

#[test]
fn relaxed_simd_fails_validation() {
    // A relaxed-SIMD instruction must not validate with the proposal off.
    let wat = r#"(module
  (func (export "f") (result v128)
    (f32x4.relaxed_madd
      (v128.const i32x4 0 0 0 0)
      (v128.const i32x4 0 0 0 0)
      (v128.const i32x4 0 0 0 0))))"#;
    let exec = executor(Backend::Native);
    let err = err_of(exec.prepare(wat.as_bytes()));
    assert!(matches!(err, InvokeError::InvalidModule { .. }), "{err}");
}

#[test]
fn memory64_fails_validation() {
    let wat = r#"(module (memory i64 1))"#;
    let exec = executor(Backend::Native);
    let err = err_of(exec.prepare(wat.as_bytes()));
    assert!(matches!(err, InvokeError::InvalidModule { .. }), "{err}");
}

#[test]
fn instances_do_not_leak_state_across_calls() {
    // handle increments a mutable global and reports the post-increment
    // value; both calls on the SAME prepared module must see the same first
    // value, proving a fresh instance backs every call.
    let counting_handle = r#"(global.set $count (i32.add (global.get $count) (i32.const 1)))
    (i32.store8 (i32.const 1024) (i32.add (i32.const 48) (global.get $count)))
    (i32.const 0)"#;
    let wat = guest_wat(counting_handle, "(i32.const 1)").replace(
        "(global $out_len (mut i32) (i32.const 0))",
        "(global $out_len (mut i32) (i32.const 0))\n  (global $count (mut i32) (i32.const 0))",
    );
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(wat.as_bytes())
        .expect("wat guest passes validation");
    let first = exec.invoke(&prepared, b"x").expect("first call");
    let second = exec.invoke(&prepared, b"x").expect("second call");
    assert_eq!(first.output, second.output);
    assert_eq!(first.output, b"1");
}

#[test]
fn oversized_input_is_rejected() {
    let exec = Executor::new(Backend::Native, budgets(|b| b.max_input_bytes = 4))
        .expect("fixed engine config is valid");
    let prepared = exec
        .prepare(guest_wat(ECHO_HANDLE, ECHO_LEN).as_bytes())
        .expect("wat guest passes validation");
    match err_of(exec.invoke(&prepared, b"12345")) {
        InvokeError::InputTooLarge { size, max } => {
            assert_eq!((size, max), (5, 4));
        }
        err => panic!("wrong error: {err}"),
    }
}

#[test]
fn guest_status_codes_map_to_distinct_errors() {
    let exec = executor(Backend::Native);
    for (status, expect_malformed) in [(1i32, true), (2, false), (7, false)] {
        let prepared = exec
            .prepare(guest_wat(&format!("(i32.const {status})"), "(i32.const 0)").as_bytes())
            .expect("wat guest passes validation");
        match err_of(exec.invoke(&prepared, b"x")) {
            InvokeError::GuestMalformedRequest => assert!(expect_malformed),
            InvokeError::GuestInternalError => assert!(!expect_malformed && status == 2),
            InvokeError::GuestStatusUnknown(seen) => assert_eq!(seen, 7),
            err => panic!("status {status}: wrong error: {err}"),
        }
    }
}

#[test]
fn out_of_bounds_result_pointer_is_rejected() {
    // 65530 + 8 = 65538 > the single 64 KiB page.
    let wat = guest_wat("(i32.const 0)", "(i32.const 8)").replacen(
        "(i32.const 1024))",
        "(i32.const 65530))",
        1,
    );
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(wat.as_bytes())
        .expect("wat guest passes validation");
    let err = err_of(exec.invoke(&prepared, b"x"));
    assert!(
        matches!(err, InvokeError::OutputOutOfBounds { .. }),
        "{err}"
    );
}

#[test]
fn guest_trap_is_surfaced_with_bounded_description() {
    let exec = executor(Backend::Native);
    let prepared = exec
        .prepare(guest_wat("(unreachable)", "(i32.const 0)").as_bytes())
        .expect("wat guest passes validation");
    match err_of(exec.invoke(&prepared, b"x")) {
        InvokeError::Trap { description } => {
            assert!(description.as_str().len() <= 128);
        }
        err => panic!("wrong error: {err}"),
    }
}
