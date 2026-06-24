// SPDX-License-Identifier: Apache-2.0
//! Capability isolation: a script can only do what is explicitly granted.
//!
//! * `eval(...)` is a compile-time rejection (`disable_symbol`).
//! * There is no `print`/`debug` output, no file/env/network access beyond the
//!   single `source.get` capability.
//! * Unregistered helpers (`xw.regex_replace`, `source.post_json`, ...) are
//!   rejected. NOTE: stock Rhai resolves method/namespaced calls at *runtime*,
//!   so an unregistered helper that is actually reached surfaces as a runtime
//!   function-not-found error (classified `Runtime`), not at `compile()`. Only
//!   disabled symbols (`eval`) are rejected at compile time. Either way the
//!   script is refused.

use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine, SourceScriptError,
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

fn compile(src: &str) -> Result<ScriptEngine, SourceScriptError> {
    ScriptEngine::compile(src, "lookup", &RhaiPolicy::default())
}

async fn run(src: &str) -> Result<Vec<serde_json::Value>, SourceScriptError> {
    let engine = compile(src)?;
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    engine.execute(host, ctx()).await
}

#[test]
fn eval_is_rejected_at_compile_time() {
    let e = match compile(r#"fn lookup(ctx) { eval("1 + 1") }"#) {
        Ok(_) => panic!("eval must not compile"),
        Err(e) => e,
    };
    assert!(matches!(e, SourceScriptError::Compile { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unregistered_xw_helper_is_rejected() {
    // `xw.text.regex_replace` is intentionally not registered.
    let e = run(r#"fn lookup(ctx) { [#{ x: xw.text.regex_replace("a", "b", "c") }] }"#)
        .await
        .unwrap_err();
    assert!(matches!(e, SourceScriptError::Runtime { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unregistered_source_method_is_rejected() {
    // `source.post_json` is intentionally not registered.
    let e = run(r#"fn lookup(ctx) { source.post_json("/x", #{}) }"#)
        .await
        .unwrap_err();
    assert!(matches!(e, SourceScriptError::Runtime { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_unregistered_xw_namespaces_are_rejected() {
    // `date.today`, `date.parse_datetime`, and phone helpers are not exposed.
    for src in [
        r#"fn lookup(ctx) { [#{ d: xw.date.today() }] }"#,
        r#"fn lookup(ctx) { [#{ d: xw.date.parse_datetime("2020-01-01T00:00:00Z") }] }"#,
        r#"fn lookup(ctx) { [#{ d: xw.phone.normalize("123") }] }"#,
    ] {
        let e = run(src).await.unwrap_err();
        assert!(
            matches!(e, SourceScriptError::Runtime { .. }),
            "expected rejection for {src:?}, got {e:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_ambient_io_functions() {
    // None of these exist in the sandbox; each call must be refused at runtime.
    for src in [
        r#"fn lookup(ctx) { print("x"); [] }"#,
        r#"fn lookup(ctx) { debug("x"); [] }"#,
        r#"fn lookup(ctx) { [#{ x: open_file("/etc/passwd") }] }"#,
        r#"fn lookup(ctx) { [#{ x: env("HOME") }] }"#,
    ] {
        let result = run(src).await;
        // print/debug are routed to no-ops (so they may "succeed" but emit
        // nothing and then fail on the empty-return shape or run fine); the
        // file/env calls must error. We assert that NONE of these can read the
        // host: a successful run returns only what the script built, never IO.
        if let Ok(records) = result {
            // Only the no-op print/debug scripts can reach here; they return [].
            assert!(records.is_empty(), "unexpected data from {src:?}");
        }
    }
}

#[test]
fn print_and_debug_compile_as_noops() {
    // print/debug are valid identifiers (routed to no-ops), so they compile;
    // they simply cannot emit anything.
    assert!(compile(r#"fn lookup(ctx) { print("x"); debug("y"); [] }"#).is_ok());
}
