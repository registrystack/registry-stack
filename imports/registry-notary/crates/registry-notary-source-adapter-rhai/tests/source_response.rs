// SPDX-License-Identifier: Apache-2.0
//! `source.get` returns a `#{ status, body }` response object, gated by the
//! engine's `visible_statuses` (P2).
//!
//! For every *observable* response — a 2xx, or a non-2xx status the engine is
//! configured to expose via `visible_statuses` — `source.get` hands the script a
//! `#{ status, body }` map so it can branch on the status (e.g. fall back to a
//! second path on a visible 404). Any other non-2xx status still terminates the
//! run as an upstream-status error, so the DEFAULT (empty `visible_statuses`)
//! behavior is unchanged: every non-2xx terminates.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine, SourceScriptError,
};
use serde_json::json;

fn ctx() -> ScriptCtx {
    ScriptCtx::new(
        "src",
        "ds",
        "ent",
        Lookup {
            field: "f".into(),
            value: "1".into(),
        },
        "verify",
    )
}

/// A policy that exposes the given non-2xx statuses to the script.
fn policy_with_visible(statuses: &[u16]) -> RhaiPolicy {
    RhaiPolicy {
        visible_statuses: statuses.iter().copied().collect::<BTreeSet<u16>>(),
        ..RhaiPolicy::default()
    }
}

// A visible 404 lets the script branch: it tries "/a" (404) and falls back to
// "/b" (200 with a body), returning the /b records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fallback_on_visible_404_branches_to_second_path() {
    let mut responses: BTreeMap<String, (u16, serde_json::Value)> = BTreeMap::new();
    responses.insert("/a".into(), (404, json!([])));
    responses.insert("/b".into(), (200, json!([{ "id": "b" }])));
    let host = Arc::new(MockScriptHost::by_path(
        Duration::from_millis(1),
        responses,
        // Fallback should never be hit in this test.
        (500, json!([])),
    ));

    let script = r#"
        fn lookup(ctx) {
            let r = source.get("t", "/a", #{});
            let data = if r.status == 404 {
                source.get("t", "/b", #{}).body
            } else {
                r.body
            };
            data
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &policy_with_visible(&[404])).unwrap();
    let out = engine.execute(host, ctx()).await.unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["id"], "b", "must return the /b body after the 404");
}

// A visible status surfaces a response object whose `status` field the script
// can read directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visible_status_returns_response_object() {
    let host = Arc::new(MockScriptHost::fixed(
        Duration::from_millis(1),
        404,
        json!([{ "id": "x" }]),
    ));
    let script = r#"
        fn lookup(ctx) {
            [#{ s: source.get("t", "/x", #{}).status }]
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &policy_with_visible(&[404])).unwrap();
    let out = engine.execute(host, ctx()).await.unwrap();
    assert_eq!(out[0]["s"], 404, "the visible status must reach the script");
}

// With the DEFAULT empty `visible_statuses`, a non-2xx status is NOT observable
// and terminates the run as an upstream-status error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_visible_non_2xx_terminates() {
    let host = Arc::new(MockScriptHost::fixed(
        Duration::from_millis(1),
        500,
        json!([]),
    ));
    let script = r#"
        fn lookup(ctx) {
            source.get("t", "/x", #{}).body
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &RhaiPolicy::default()).unwrap();
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::HttpStatus { status: 500 }),
        "a non-visible 500 must terminate as HttpStatus {{ 500 }}, got {e:?}"
    );
}

// A 2xx response is wrapped in the response object too; `.body` yields the
// echoed records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn success_2xx_is_wrapped() {
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let script = r#"
        fn lookup(ctx) {
            source.get("t", "/x", #{ value: ctx.lookup.value }).body
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &RhaiPolicy::default()).unwrap();
    let out = engine.execute(host, ctx()).await.unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0]["id"], "t/x",
        "the echoed record must come back via .body"
    );
    assert_eq!(out[0]["v"], "1");
}

// `source.post_json` has the same response shape as `source.get`, but carries a
// host-owned JSON body to the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_json_success_2xx_is_wrapped() {
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let script = r#"
        fn lookup(ctx) {
            source.post_json(
                "t",
                "/search",
                #{ value: ctx.lookup.value },
                #{ q: ctx.lookup.value, limit: 1 }
            ).body
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &RhaiPolicy::default()).unwrap();
    let out = engine.execute(host, ctx()).await.unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["id"], "t/search");
    assert_eq!(out[0]["v"], "1");
    assert_eq!(out[0]["body"], json!({ "q": "1", "limit": 1 }));
}
