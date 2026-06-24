// SPDX-License-Identifier: Apache-2.0
//! Output-shape validation, exercised through the engine: the script return
//! must be an array of plain objects, capped at the record limit, with no
//! functions / opaque handles.

use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    BudgetKind, Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine, SourceScriptError,
    MAX_RECORDS,
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

async fn run(script: &str) -> Result<Vec<serde_json::Value>, SourceScriptError> {
    let engine = ScriptEngine::compile(script, "lookup", &RhaiPolicy::default()).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    engine.execute(host, ctx()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepts_array_of_objects() {
    let out = run(r#"fn lookup(ctx) { [#{ a: 1 }, #{ b: "two" }] }"#)
        .await
        .unwrap();
    assert_eq!(out.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_scalar_top_level() {
    let e = run(r#"fn lookup(ctx) { 42 }"#).await.unwrap_err();
    assert!(matches!(e, SourceScriptError::Type { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_string_top_level() {
    let e = run(r#"fn lookup(ctx) { "nope" }"#).await.unwrap_err();
    assert!(matches!(e, SourceScriptError::Type { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_object_top_level() {
    let e = run(r#"fn lookup(ctx) { #{ a: 1 } }"#).await.unwrap_err();
    assert!(matches!(e, SourceScriptError::Type { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_non_object_item() {
    let e = run(r#"fn lookup(ctx) { [1, 2, 3] }"#).await.unwrap_err();
    assert!(matches!(e, SourceScriptError::Type { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_function_pointer_in_output() {
    // A function pointer in the output is not plain data -> Type error.
    let e = run(r#"fn lookup(ctx) { [#{ f: Fn("foo") }] }"#)
        .await
        .unwrap_err();
    assert!(matches!(e, SourceScriptError::Type { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_more_than_max_records() {
    let src = format!(
        r#"fn lookup(ctx) {{ let a = []; for i in 0..{} {{ a.push(#{{ i: i }}); }} a }}"#,
        MAX_RECORDS + 1
    );
    let e = run(&src).await.unwrap_err();
    assert!(matches!(e, SourceScriptError::Type { .. }), "got {e:?}");

    // Exactly the cap is allowed.
    let src_ok = format!(
        r#"fn lookup(ctx) {{ let a = []; for i in 0..{MAX_RECORDS} {{ a.push(#{{ i: i }}); }} a }}"#
    );
    assert_eq!(run(&src_ok).await.unwrap().len(), MAX_RECORDS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn output_byte_cap_enforced() {
    // A small output cap, with a script that returns a large string field.
    let policy = RhaiPolicy {
        max_output_bytes: 256,
        ..RhaiPolicy::default()
    };
    let engine = ScriptEngine::compile(
        r#"fn lookup(ctx) { let s = "x"; for i in 0..12 { s += s; } [#{ s: s }] }"#,
        "lookup",
        &policy,
    )
    .unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(
        matches!(
            e,
            SourceScriptError::Budget {
                kind: BudgetKind::OutputBytes
            }
        ),
        "got {e:?}"
    );
}
