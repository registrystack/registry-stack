// SPDX-License-Identifier: Apache-2.0
//! End-to-end proof that the path-canonicalization gate (B2) is actually
//! invoked by the `source.get` capability, BEFORE the host is ever called.
//!
//! Before the fix, the raw script path was passed straight to the host and the
//! canonicalizer was dead code. These tests assert that a traversal path and an
//! encoded-separator path are rejected with `HostDenied` and that the host saw
//! ZERO calls — i.e. the rejection happens pre-dispatch — while a clean path is
//! canonicalized and reaches the host normally.

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
            value: "1".into(),
        },
        "verify",
    )
}

/// Run a script that calls `source.get` with the given literal path. Returns
/// the result plus the host's started-call count so the test can assert the
/// host was (or was not) reached.
async fn run_with_path(path: &str) -> (Result<Vec<serde_json::Value>, SourceScriptError>, u64) {
    let script = format!(
        r#"fn lookup(ctx) {{ source.get("t", "{path}", #{{ value: ctx.lookup.value }}) }}"#
    );
    let engine = ScriptEngine::compile(&script, "lookup", &RhaiPolicy::default()).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let res = engine.execute(host.clone(), ctx()).await;
    (res, host.started())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traversal_path_is_rejected_before_host_is_called() {
    let (res, started) = run_with_path("/a/../b").await;
    let e = res.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::HostDenied { .. }),
        "traversal path must be HostDenied, got {e:?}"
    );
    assert_eq!(
        started, 0,
        "host must NOT be called for a rejected traversal path"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_separator_path_is_rejected_before_host_is_called() {
    let (res, started) = run_with_path("/a%2fb").await;
    let e = res.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::HostDenied { .. }),
        "encoded-separator path must be HostDenied, got {e:?}"
    );
    assert_eq!(
        started, 0,
        "host must NOT be called for a rejected encoded-separator path"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_relative_path_is_rejected_before_host_is_called() {
    let (res, started) = run_with_path("//evil.com/x").await;
    let e = res.unwrap_err();
    assert!(
        matches!(e, SourceScriptError::HostDenied { .. }),
        "protocol-relative path must be HostDenied, got {e:?}"
    );
    assert_eq!(started, 0, "host must NOT be called for a rejected path");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_path_is_canonicalized_and_reaches_host() {
    // A clean path passes the gate; the host is called and the echo comes back,
    // proving the gate does not block legitimate requests. The echoed id is
    // "<target><path>", confirming the canonical path reached the host.
    let (res, started) = run_with_path("/a/b").await;
    let out = res.expect("clean path must succeed");
    assert_eq!(started, 1, "host should have been called exactly once");
    assert_eq!(out[0]["id"], "t/a/b");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn percent_encoded_clean_path_is_decoded_before_host() {
    // `%61` -> `a`: a safe encoded character decodes during canonicalization,
    // so the host sees the decoded form, not the raw escape.
    let (res, started) = run_with_path("/%61/b").await;
    let out = res.expect("safe encoded path must succeed");
    assert_eq!(started, 1);
    assert_eq!(out[0]["id"], "t/a/b");
}
