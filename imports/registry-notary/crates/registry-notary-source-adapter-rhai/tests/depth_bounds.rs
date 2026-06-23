// SPDX-License-Identifier: Apache-2.0
//! Hostile-depth regression tests (B1).
//!
//! An adversarial script can build a data structure thousands of levels deep.
//! The configured width caps (`max_array_items`, `max_map_entries`,
//! `max_call_levels`) do NOT bound *nesting depth*, and the recursive
//! validators plus Rhai/serde's own recursive (de)serializers would overflow
//! the blocking thread's stack and ABORT the process — uncatchable by the panic
//! boundary and fatal to every concurrent execution.
//!
//! Depth-guard coverage is split across two layers, by necessity:
//!
//! * The authoritative *~5000-deep* proofs live in the `convert` and `output`
//!   unit tests. There the over-depth value is constructed on the test runner's
//!   main thread (which has a large stack), so it can be built at all; the guard
//!   then rejects it at [`MAX_JSON_DEPTH`] **before** any recursive serializer
//!   (`to_dynamic` / `to_value`) runs. That is the real fix being proven.
//!
//! * These end-to-end tests prove the guard is actually *wired into* the three
//!   reachable conversions (script output, host body, `credential_public`).
//!   They run on tokio worker / blocking threads whose stacks are only ~2 MiB,
//!   on which merely *constructing* a 5000-deep value (in the script evaluator
//!   or in serde) would itself overflow before the guard could run. They
//!   therefore use a depth that is unambiguously hostile — many times the cap —
//!   yet still constructible on a small stack, and assert a controlled `Type`
//!   error with no abort.
//!
//! If the guard regressed, these tests would not merely fail an assertion: the
//! recursive converter would overflow and the whole test binary would SIGABRT.

use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    convert::MAX_JSON_DEPTH, Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine,
    SourceScriptError,
};
use serde_json::{json, Value};

/// A depth far above the cap (so it decisively exercises the guard) but small
/// enough to construct on a ~2 MiB tokio thread without the *constructor*
/// overflowing. The ~5000-deep guarantee is proven in the conversion unit tests.
const HOSTILE_DEPTH: usize = 600;

// Compile-time guarantee that the chosen depth actually exceeds the cap.
const _: () = assert!(HOSTILE_DEPTH > MAX_JSON_DEPTH);

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

/// Generous limits so the *depth* guard — not the operation budget or wall
/// clock — is the thing under test. `max_operations` stays finite (as in
/// production) so it remains a backstop rather than `0`/unlimited.
fn policy() -> RhaiPolicy {
    let mut p = RhaiPolicy {
        timeout: Duration::from_secs(10),
        ..RhaiPolicy::default()
    };
    p.limits.max_operations = 50_000_000;
    p
}

// (B1, output direction) A script that nests `HOSTILE_DEPTH` arrays deep around
// a value and returns it must be rejected with a controlled `Type` error,
// because `dynamic_to_json` rejects at the depth cap before the recursive
// serializer / validator runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_returning_hostile_depth_is_rejected_not_aborted() {
    let script = format!(
        r#"
        fn lookup(ctx) {{
            let x = 0;
            for i in 0..{HOSTILE_DEPTH} {{
                x = [x];
            }}
            [#{{ d: x }}]
        }}
    "#
    );
    let engine = ScriptEngine::compile(&script, "lookup", &policy()).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::Type { .. }),
        "hostile output depth must classify as a Type error, got {e:?}"
    );
}

// (B1, input direction) A host whose response `body` nests `HOSTILE_DEPTH`
// levels deep must be rejected when converted into a Rhai `Dynamic` for the
// script — `json_to_dynamic` checks depth before `to_dynamic`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_body_with_hostile_depth_is_rejected_not_aborted() {
    let mut deep: Value = json!(0);
    for _ in 0..HOSTILE_DEPTH {
        deep = Value::Array(vec![deep]);
    }
    let body = json!([{ "d": deep }]);

    let script = r#"
        fn lookup(ctx) {
            source.get("t", "/path", #{ value: ctx.lookup.value })
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &policy()).unwrap();
    let host = Arc::new(MockScriptHost::fixed(Duration::from_millis(1), 200, body));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::Type { .. }),
        "hostile host-body depth must classify as a Type error, got {e:?}"
    );
}

// (B1, ctx direction) A deeply nested `credential_public` (json -> dynamic on
// the way *in* to the script) must likewise be rejected, proving the third
// reachable conversion is guarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctx_credential_public_with_hostile_depth_is_rejected_not_aborted() {
    let mut deep: Value = json!(0);
    for _ in 0..HOSTILE_DEPTH {
        deep = Value::Array(vec![deep]);
    }
    let ctx = ScriptCtx::new(
        "src",
        "ds",
        "ent",
        Lookup {
            field: "f".into(),
            value: "x".into(),
        },
        "verify",
    )
    .credential_public(json!({ "deep": deep }));

    let script = r#"fn lookup(ctx) { [#{ ok: true }] }"#;
    let engine = ScriptEngine::compile(script, "lookup", &policy()).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let e = engine.execute(host, ctx).await.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::Type { .. }),
        "hostile credential_public depth must classify as a Type error, got {e:?}"
    );
}
