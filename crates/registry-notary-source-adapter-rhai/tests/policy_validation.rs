// SPDX-License-Identifier: Apache-2.0
//! Fail-fast policy validation in `ScriptEngine::compile` (P2).
//!
//! An out-of-contract policy is rejected up front with a
//! [`SourceScriptError::Config`] rather than being silently coerced (the old
//! `max_concurrent == 0 -> 1`) or accepted with a footgun meaning
//! (`max_operations == 0` disables Rhai's runaway-loop backstop). A fully valid
//! policy still compiles.

use registry_notary_source_adapter_rhai::{RhaiPolicy, ScriptEngine, SourceScriptError};

/// A trivially valid script with the expected entrypoint.
const VALID: &str = r#"fn lookup(ctx) { [#{ ok: true }] }"#;

/// Extract the error without requiring `Debug` on the Ok type (`ScriptEngine`).
fn err_of(r: Result<ScriptEngine, SourceScriptError>) -> SourceScriptError {
    match r {
        Ok(_) => panic!("expected a Config error"),
        Err(e) => e,
    }
}

/// Assert that compiling `VALID` with `policy` fails with a `Config` error.
fn assert_config_rejected(policy: &RhaiPolicy, case: &str) {
    let e = err_of(ScriptEngine::compile(VALID, "lookup", policy));
    assert!(
        matches!(e, SourceScriptError::Config { .. }),
        "case {case}: expected Config error, got {e:?}"
    );
}

#[test]
fn rejects_zero_max_operations() {
    let mut p = RhaiPolicy::default();
    p.limits.max_operations = 0;
    assert_config_rejected(&p, "max_operations=0");
}

#[test]
fn rejects_nonzero_max_modules() {
    let mut p = RhaiPolicy::default();
    p.limits.max_modules = 1;
    assert_config_rejected(&p, "max_modules=1");
}

#[test]
fn rejects_zero_max_http_calls() {
    let p = RhaiPolicy {
        max_http_calls: 0,
        ..RhaiPolicy::default()
    };
    assert_config_rejected(&p, "max_http_calls=0");
}

#[test]
fn rejects_max_http_calls_over_hard_max() {
    let p = RhaiPolicy {
        max_http_calls: 6,
        ..RhaiPolicy::default()
    };
    assert_config_rejected(&p, "max_http_calls=6");
}

#[test]
fn rejects_zero_max_concurrent() {
    let p = RhaiPolicy {
        max_concurrent: 0,
        ..RhaiPolicy::default()
    };
    assert_config_rejected(&p, "max_concurrent=0");
}

#[test]
fn rejects_zero_timeout() {
    let p = RhaiPolicy {
        timeout: std::time::Duration::ZERO,
        ..RhaiPolicy::default()
    };
    assert_config_rejected(&p, "timeout=0");
}

#[test]
fn rejects_zero_max_output_bytes() {
    let p = RhaiPolicy {
        max_output_bytes: 0,
        ..RhaiPolicy::default()
    };
    assert_config_rejected(&p, "max_output_bytes=0");
}

#[test]
fn valid_policy_compiles_ok() {
    // The default policy is in-contract; at the hard ceiling it is still valid.
    assert!(ScriptEngine::compile(VALID, "lookup", &RhaiPolicy::default()).is_ok());
    let at_ceiling = RhaiPolicy {
        max_http_calls: 5,
        ..RhaiPolicy::default()
    };
    assert!(ScriptEngine::compile(VALID, "lookup", &at_ceiling).is_ok());
}
