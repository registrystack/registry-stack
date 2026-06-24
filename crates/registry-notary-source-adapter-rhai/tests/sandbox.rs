// SPDX-License-Identifier: Apache-2.0
//! Sandbox resource limits, exercised end-to-end through the engine. Each
//! hostile script must be terminated (the engine returns an error rather than
//! looping forever or exhausting memory).
//!
//! Axes: operations, call depth, string size, array size, map-literal size, and
//! the computed-key map case that is bounded by operations.

use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    BudgetKind, Lookup, MockScriptHost, RhaiLimits, RhaiPolicy, ScriptCtx, ScriptEngine,
    SourceScriptError,
};

fn ctx() -> ScriptCtx {
    ScriptCtx::new(
        "src",
        "ds",
        "ent",
        Lookup {
            field: "f".into(),
            value: "x".into(),
        },
        "verify",
    )
}

/// A policy with deliberately tiny limits so hostile scripts trip fast, and a
/// generous wall-clock so the *resource* limit (not the deadline) is the cause.
fn tiny_policy() -> RhaiPolicy {
    RhaiPolicy {
        limits: RhaiLimits {
            max_operations: 100_000,
            max_call_levels: 16,
            max_string_bytes: 1_024,
            max_array_items: 256,
            max_map_entries: 256,
            max_modules: 0,
        },
        timeout: Duration::from_secs(10),
        ..RhaiPolicy::default()
    }
}

async fn run(script: &str) -> Result<Vec<serde_json::Value>, SourceScriptError> {
    let engine = ScriptEngine::compile(script, "lookup", &tiny_policy()).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    engine.execute(host, ctx()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operations_budget_terminates_infinite_loop() {
    let e = run(r#"fn lookup(ctx) { let i = 0; while true { i += 1; } [] }"#)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            SourceScriptError::Budget {
                kind: BudgetKind::Operations
            }
        ),
        "got {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_depth_terminates_infinite_recursion() {
    let e = run(r#"fn rec(n) { rec(n + 1) } fn lookup(ctx) { rec(0) }"#)
        .await
        .unwrap_err();
    // Classified as a Runtime error (call-depth phrasing), not a budget.
    assert!(matches!(e, SourceScriptError::Runtime { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn string_size_terminates_runaway_growth() {
    let e = run(r#"fn lookup(ctx) { let s = "x"; while true { s += s; } [] }"#)
        .await
        .unwrap_err();
    assert!(matches!(e, SourceScriptError::Runtime { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn array_size_terminates_runaway_growth() {
    let e = run(r#"fn lookup(ctx) { let a = []; while true { a.push(1); } [] }"#)
        .await
        .unwrap_err();
    assert!(matches!(e, SourceScriptError::Runtime { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn map_literal_over_limit_is_rejected() {
    // A map literal with more than `max_map_entries` entries is rejected. In
    // rhai 1.25.1 this is caught at COMPILE time ("Number of properties in
    // object map literal exceeds the maximum limit"), which is a strictly
    // stronger guarantee than a runtime check.
    let mut src = String::from("fn lookup(ctx) { let m = #{");
    for i in 0..300 {
        src.push_str(&format!("k{i}: {i},"));
    }
    src.push_str("}; [m] }");

    match ScriptEngine::compile(&src, "lookup", &tiny_policy()) {
        // Rejected at compile time: the strongest outcome.
        Err(SourceScriptError::Compile { .. }) => {}
        // If a future rhai version defers it, it must still be rejected at run.
        Err(other) => panic!("unexpected compile error: {other:?}"),
        Ok(_) => {
            let e = run(&src).await.unwrap_err();
            assert!(matches!(e, SourceScriptError::Runtime { .. }), "got {e:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn computed_key_map_growth_is_bounded_by_operations() {
    // A computed-key indexer-insert loop is NOT re-checked against map-size each
    // iteration; it is reliably stopped by the operations budget. With ops
    // capped, an unbounded map is impossible -- the binding limit is ops.
    let e = run(
        r#"fn lookup(ctx) { let m = #{}; let i = 0; while true { m["k" + i] = i; i += 1; } [] }"#,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            e,
            SourceScriptError::Budget {
                kind: BudgetKind::Operations
            }
        ),
        "expected operations budget (not map-size), got {e:?}"
    );
}
