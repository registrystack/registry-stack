// SPDX-License-Identifier: Apache-2.0
//! The `xw` helper namespace, exercised through the engine with dotted syntax.
//! Confirms a couple of correctness cases per namespace and that the helpers
//! are pure (same input -> same output, no host call required).

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

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

/// Run a script that returns `[#{ r: <expr> }]` and yield the `r` value.
async fn eval_r(body_expr: &str) -> Result<Value, SourceScriptError> {
    let src = format!("fn lookup(ctx) {{ [#{{ r: {body_expr} }}] }}");
    let engine = ScriptEngine::compile(&src, "lookup", &RhaiPolicy::default()).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let out = engine.execute(host, ctx()).await?;
    Ok(out[0]["r"].clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_namespace() {
    assert_eq!(
        eval_r(r#"xw.text.slug("Hello, WORLD!")"#).await.unwrap(),
        "hello-world"
    );
    assert_eq!(eval_r(r#"xw.text.trim("  a  ")"#).await.unwrap(), "a");
    assert_eq!(
        eval_r(r#"xw.text.title_simple("ada lovelace")"#)
            .await
            .unwrap(),
        "Ada Lovelace"
    );
    assert_eq!(
        eval_r(r#"xw.text.remove_accents("Crème Brûlée")"#)
            .await
            .unwrap(),
        "Creme Brulee"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn date_namespace() {
    assert_eq!(
        eval_r(r#"xw.date.add_days("2024-01-01", 2)"#)
            .await
            .unwrap(),
        "2024-01-03"
    );
    assert_eq!(
        eval_r(r#"xw.date.add_months("2024-01-31", 1)"#)
            .await
            .unwrap(),
        "2024-02-29"
    );
    assert_eq!(
        eval_r(r#"xw.date.age_on("2000-05-27", "2026-05-26")"#)
            .await
            .unwrap(),
        25
    );
    assert_eq!(
        eval_r(r#"xw.date.end_of_month("2024-02-15")"#)
            .await
            .unwrap(),
        "2024-02-29"
    );
    // A parse error maps to a Runtime error (the helper's stable code).
    let e = eval_r(r#"xw.date.parse_date("not-a-date")"#)
        .await
        .unwrap_err();
    assert!(matches!(e, SourceScriptError::Runtime { .. }), "got {e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ids_namespace() {
    assert_eq!(
        eval_r(r#"xw.ids.stable_hash_sha256("abc")"#).await.unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_r(r#"xw.ids.prefixed_slug("ps", "Hello World!")"#)
            .await
            .unwrap(),
        "ps_hello-world"
    );
    assert_eq!(
        eval_r(r#"xw.ids.clean_id("a b_c-d!")"#).await.unwrap(),
        "ab_c-d"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_namespace() {
    // parse_json then read a field. Build the JSON string from a char to avoid
    // escaped-quote literals tripping the parser's complexity guard.
    let src = r#"
        fn lookup(ctx) {
            let q = "\"";
            let text = "{" + q + "b" + q + ":2}";
            let parsed = xw.json.parse_json(text);
            [#{ r: parsed.b }]
        }
    "#;
    let engine = ScriptEngine::compile(src, "lookup", &RhaiPolicy::default()).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let out = engine.execute(host, ctx()).await.unwrap();
    assert_eq!(out[0]["r"], 2);

    // stringify a map (bind the map first to keep the expression shallow).
    let src2 = r#"
        fn lookup(ctx) {
            let m = #{ b: 2 };
            let s = xw.json.stringify_json(m);
            [#{ r: s }]
        }
    "#;
    let engine2 = ScriptEngine::compile(src2, "lookup", &RhaiPolicy::default()).unwrap();
    let host2 = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let out2 = engine2.execute(host2, ctx()).await.unwrap();
    assert_eq!(out2[0]["r"], "{\"b\":2}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_namespace() {
    assert_eq!(
        eval_r(r#"xw.email.normalize_email(" USER@Example.ORG ")"#)
            .await
            .unwrap(),
        "user@example.org"
    );
    assert_eq!(
        eval_r(r#"xw.email.email_domain("user@example.org")"#)
            .await
            .unwrap(),
        "example.org"
    );
    assert_eq!(
        eval_r(r#"xw.email.is_valid_email("a@b")"#).await.unwrap(),
        true
    );
    assert_eq!(
        eval_r(r#"xw.email.is_valid_email("@b")"#).await.unwrap(),
        false
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redaction_namespace() {
    assert_eq!(
        eval_r(r#"xw.redaction.mask("123456789", 4)"#)
            .await
            .unwrap(),
        "*****6789"
    );
    assert_eq!(
        eval_r(r#"xw.redaction.redact()"#).await.unwrap(),
        "[REDACTED]"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn helpers_are_pure_and_deterministic() {
    // The same call evaluated twice yields the same value, with no host call.
    let a = eval_r(r#"xw.ids.stable_hash_sha256("seed", "salt")"#)
        .await
        .unwrap();
    let b = eval_r(r#"xw.ids.stable_hash_sha256("seed", "salt")"#)
        .await
        .unwrap();
    assert_eq!(a, b);
}
