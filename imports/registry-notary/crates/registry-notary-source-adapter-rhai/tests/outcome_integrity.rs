// SPDX-License-Identifier: Apache-2.0
//! Outcome-integrity regression tests (M1).
//!
//! A script must not be able to forge its own terminal classification by
//! `throw`ing a string that looks like an internal marker. The authoritative
//! cause is recorded out-of-band by the host-trusted code that forces
//! termination, and classification reads that cell first.
//!
//! These tests pair each forged throw with the corresponding *real* condition:
//! the forged throw must classify as a plain `Runtime` (script-controlled)
//! error, while the real condition must still classify correctly.

use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    BudgetKind, Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine, SourceScriptError,
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

async fn run_script(script: &str, policy: &RhaiPolicy) -> SourceScriptError {
    let engine = ScriptEngine::compile(script, "lookup", policy).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    engine.execute(host, ctx()).await.unwrap_err()
}

// --- Forged throws must all classify as Runtime (script-controlled) ---

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_deadline_throw_is_runtime_not_deadline() {
    let e = run_script(
        r#"fn lookup(ctx) { throw "deadline_exceeded" }"#,
        &RhaiPolicy::default(),
    )
    .await;
    assert!(
        matches!(e, SourceScriptError::Runtime { .. }),
        "a thrown 'deadline_exceeded' must be a Runtime error, got {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_http_budget_throw_is_runtime_not_budget() {
    let e = run_script(
        r#"fn lookup(ctx) { throw "__xw_http_budget__" }"#,
        &RhaiPolicy::default(),
    )
    .await;
    assert!(
        matches!(e, SourceScriptError::Runtime { .. }),
        "a thrown budget marker must be a Runtime error, got {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_host_status_throw_is_runtime_not_http_status() {
    let e = run_script(
        r#"fn lookup(ctx) { throw "__xw_host__:status:503" }"#,
        &RhaiPolicy::default(),
    )
    .await;
    assert!(
        matches!(e, SourceScriptError::Runtime { .. }),
        "a thrown host-status marker must be a Runtime error, got {e:?}"
    );
    // And it must NOT inherit the 503 problem-code classification.
    assert_ne!(
        e.kind(),
        "http_status",
        "forged status must not classify as http_status"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_operations_throw_is_runtime_not_budget() {
    // The resource-limit path is read from Rhai's typed error variant, not the
    // Display string, so throwing the phrasing cannot forge an Operations budget.
    let e = run_script(
        r#"fn lookup(ctx) { throw "too many operations" }"#,
        &RhaiPolicy::default(),
    )
    .await;
    assert!(
        matches!(e, SourceScriptError::Runtime { .. }),
        "a thrown 'too many operations' must be a Runtime error, got {e:?}"
    );
}

// --- The real conditions must still classify correctly ---

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_deadline_still_classifies_as_deadline() {
    let policy = RhaiPolicy {
        timeout: Duration::from_millis(100),
        ..RhaiPolicy::default()
    };
    let script = r#"
        fn lookup(ctx) {
            source.get("t", "/path", #{ value: ctx.lookup.value }).body
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &policy).unwrap();
    // Host sleeps far past the deadline so the real deadline fires.
    let host = Arc::new(MockScriptHost::echo(Duration::from_secs(3)));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::Deadline),
        "real deadline must classify as Deadline, got {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_budget_breach_still_classifies_as_budget() {
    let policy = RhaiPolicy {
        max_http_calls: 2,
        ..RhaiPolicy::default()
    };
    let script = r#"
        fn lookup(ctx) {
            let acc = [];
            for i in 0..10 {
                let r = source.get("t", "/p", #{ value: i }).body;
                acc.push(r[0]);
            }
            acc
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &policy).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(
        matches!(
            e,
            SourceScriptError::Budget {
                kind: BudgetKind::HttpCalls
            }
        ),
        "real budget breach must classify as Budget(HttpCalls), got {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_host_503_still_classifies_as_http_status() {
    let script = r#"
        fn lookup(ctx) {
            source.get("t", "/path", #{ value: ctx.lookup.value }).body
        }
    "#;
    let engine = ScriptEngine::compile(script, "lookup", &RhaiPolicy::default()).unwrap();
    let host = Arc::new(MockScriptHost::fixed(
        Duration::from_millis(1),
        503,
        json!([]),
    ));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::HttpStatus { status: 503 }),
        "real host 503 must classify as HttpStatus {{ 503 }}, got {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_operations_budget_still_classifies_as_budget() {
    // A genuine operation-budget exhaustion (Rhai's typed error) must classify
    // as Budget(Operations), proving the variant-based path still works.
    let policy = RhaiPolicy {
        timeout: Duration::from_secs(10),
        ..RhaiPolicy::default()
    };
    let e = run_script(
        r#"fn lookup(ctx) { let i = 0; while true { i += 1; } [] }"#,
        &policy,
    )
    .await;
    assert!(
        matches!(
            e,
            SourceScriptError::Budget {
                kind: BudgetKind::Operations
            }
        ),
        "real operations exhaustion must classify as Budget(Operations), got {e:?}"
    );
}
