// SPDX-License-Identifier: Apache-2.0
//! End-to-end happy-path execution: a script reads `ctx.lookup.value`, calls
//! `source.get`, and returns an array of objects.

use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine, ScriptSourceHost,
};

const LOOKUP: &str = r#"
fn lookup(ctx) {
    let v = ctx.lookup.value;
    let rows = source.get("t", "/path", #{ value: v });
    rows
}
"#;

fn ctx(value: &str) -> ScriptCtx {
    ScriptCtx::new(
        "src",
        "ds",
        "ent",
        Lookup {
            field: "f".into(),
            value: value.into(),
        },
        "verify",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_returns_array_of_objects() {
    let host: Arc<dyn ScriptSourceHost> = Arc::new(MockScriptHost::echo(Duration::from_millis(2)));
    let engine = ScriptEngine::compile(LOOKUP, "lookup", &RhaiPolicy::default()).unwrap();

    let out = engine.execute(host, ctx("7")).await.unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["id"], "t/path");
    assert_eq!(out[0]["v"], "7");

    let (completed, ..) = engine.counters().snapshot();
    assert_eq!(completed, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_can_use_xw_helpers_in_pipeline() {
    // Build a record purely from xw helpers (no host call) and return it.
    const S: &str = r#"
        fn lookup(ctx) {
            let name = xw.text.title_simple(ctx.lookup.value);
            let id = xw.ids.clean_id(ctx.lookup.value);
            [#{ name: name, id: id }]
        }
    "#;
    let host: Arc<dyn ScriptSourceHost> = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let engine = ScriptEngine::compile(S, "lookup", &RhaiPolicy::default()).unwrap();
    let out = engine.execute(host, ctx("ada lovelace!")).await.unwrap();
    assert_eq!(out[0]["name"], "Ada Lovelace!");
    assert_eq!(out[0]["id"], "adalovelace");
}
