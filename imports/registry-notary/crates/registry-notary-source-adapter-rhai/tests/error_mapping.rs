// SPDX-License-Identifier: Apache-2.0
//! End-to-end mapping of host outcomes to the error taxonomy and the stable
//! public problem codes.

use std::sync::Arc;
use std::time::Duration;

use registry_notary_source_adapter_rhai::{
    problem_code, BudgetKind, Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine,
    SourceScriptError,
};
use serde_json::json;

const CALL: &str = r#"
fn lookup(ctx) {
    source.get("t", "/path", #{ value: ctx.lookup.value }).body
}
"#;

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

async fn run_with_status(status: u16) -> SourceScriptError {
    let engine = ScriptEngine::compile(CALL, "lookup", &RhaiPolicy::default()).unwrap();
    let host = Arc::new(MockScriptHost::fixed(
        Duration::from_millis(1),
        status,
        json!([]),
    ));
    engine.execute(host, ctx()).await.unwrap_err()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_2xx_status_maps_to_http_status_error() {
    for status in [400u16, 401, 403, 429, 500, 503, 504] {
        let e = run_with_status(status).await;
        assert!(
            matches!(e, SourceScriptError::HttpStatus { status: s } if s == status),
            "status {status} -> {e:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn problem_codes_follow_the_public_contract() {
    assert_eq!(
        run_with_status(401).await.problem_code(),
        problem_code::TARGET_AUTH
    );
    assert_eq!(
        run_with_status(403).await.problem_code(),
        problem_code::TARGET_AUTH
    );
    assert_eq!(
        run_with_status(429).await.problem_code(),
        problem_code::TARGET_RATE_LIMIT
    );
    assert_eq!(
        run_with_status(504).await.problem_code(),
        problem_code::TIMEOUT
    );
    assert_eq!(
        run_with_status(500).await.problem_code(),
        problem_code::UNAVAILABLE
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_failure_maps_to_unavailable() {
    let engine = ScriptEngine::compile(CALL, "lookup", &RhaiPolicy::default()).unwrap();
    let host = Arc::new(MockScriptHost::transport_failure(Duration::from_millis(1)));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(matches!(e, SourceScriptError::HttpTransport));
    assert_eq!(e.problem_code(), problem_code::UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_call_budget_is_enforced() {
    // A script that loops calling source.get past the budget gets a Budget error.
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
        "got {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_maps_to_timeout_problem_code() {
    let policy = RhaiPolicy {
        timeout: Duration::from_millis(100),
        ..RhaiPolicy::default()
    };
    let engine = ScriptEngine::compile(CALL, "lookup", &policy).unwrap();
    // Host sleeps far past the deadline.
    let host = Arc::new(MockScriptHost::echo(Duration::from_secs(3)));
    let e = engine.execute(host, ctx()).await.unwrap_err();
    assert!(matches!(e, SourceScriptError::Deadline));
    assert_eq!(e.problem_code(), problem_code::TIMEOUT);
}
