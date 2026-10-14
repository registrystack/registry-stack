// SPDX-License-Identifier: Apache-2.0
//! The pure function profile computes over RFC 3339 instants without a clock:
//! `add_seconds` moves an instant and `seconds_between` measures two. Their
//! refusals are ordinary function failures that omit the refused values.
use registry_coordinator::{authoring, definition::Definition};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs};

const FUNCTIONS: &str = r#"
fn due(inputs) { add_seconds(inputs.request.at, inputs.request.seconds) }
fn elapsed(inputs) { seconds_between(inputs.request.at, inputs.request.other) }
fn clock(inputs) { timestamp() }
"#;

fn definition() -> Definition {
    let workflow = json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "instants", "version": "1"},
        "functions": {
            "due": {"runtime":"rhai","source":"functions.rhai","entrypoint":"due","inputs":{"request":{"type":"object"}},"output":{"type":"string","format":"date-time"}},
            "clock": {"runtime":"rhai","source":"functions.rhai","entrypoint":"clock","inputs":{"request":{"type":"object"}},"output":{"type":"string","format":"date-time"}},
            "elapsed": {"runtime":"rhai","source":"functions.rhai","entrypoint":"elapsed","inputs":{"request":{"type":"object"}},"output":{"type":"integer"}}
        },
        "workflow": {"input": {"type": "object"}, "deadlineSeconds": 86400, "start": "due",
            "steps": {
                "due": {"type": "wait-until", "waitUntil": {"type": "function", "function": "due", "inputs": {"request":{"type": "input"}}}, "next": "clock"},
                "clock": {"type": "wait-until", "waitUntil": {"type": "function", "function": "clock", "inputs": {"request":{"type": "input"}}}, "next": "done"},
                "done": {"type": "finish", "outcome": "measured", "output": {"type": "function", "function": "elapsed", "inputs": {"request":{"type": "input"}}}}
            }, "outcomes": {"measured": {"type": "integer"}}
        }
    });
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string(&workflow).unwrap(),
    )
    .unwrap();
    fs::write(root.path().join("functions.rhai"), FUNCTIONS).unwrap();
    Definition::load(root.path()).unwrap()
}

fn shifted(at: &str, seconds: Value) -> registry_coordinator::Result<Value> {
    definition().evaluate(
        "due",
        &json!({"at": at, "seconds": seconds}),
        &BTreeMap::new(),
    )
}

fn between(at: &str, other: &str) -> registry_coordinator::Result<Value> {
    definition().evaluate("done", &json!({"at": at, "other": other}), &BTreeMap::new())
}

const REFUSED: &str = "the function could not evaluate its supplied values";

#[test]
fn add_seconds_moves_an_instant_and_writes_it_in_utc() {
    for (at, seconds, expected) in [
        ("2026-10-09T09:00:00Z", 86_400, "2026-10-10T09:00:00Z"),
        ("2026-10-09T09:00:00+02:00", -3_600, "2026-10-09T06:00:00Z"),
        ("2026-10-09T09:00:00.250Z", 1, "2026-10-09T09:00:01.250Z"),
        ("2026-10-09T09:00:00Z", 0, "2026-10-09T09:00:00Z"),
    ] {
        assert_eq!(
            shifted(at, json!(seconds)).unwrap(),
            json!(expected),
            "{at} {seconds}"
        );
    }
}

#[test]
fn seconds_between_counts_whole_seconds_from_the_first_instant_to_the_second() {
    for (at, other, expected) in [
        (
            "2026-10-09T09:00:00Z",
            "2026-10-10T09:00:00+01:00",
            82_800_i64,
        ),
        ("2026-10-10T09:00:00+01:00", "2026-10-09T09:00:00Z", -82_800),
        ("2026-10-09T09:00:00Z", "2026-10-09T09:00:01.900Z", 1),
        ("2026-10-09T09:00:01.900Z", "2026-10-09T09:00:00Z", -1),
        (
            "0000-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
            315_569_519_999,
        ),
    ] {
        assert_eq!(between(at, other).unwrap(), json!(expected), "{at} {other}");
    }
}

#[test]
fn an_instant_or_result_outside_rfc_3339_is_a_function_failure_that_omits_the_values() {
    let canary = "synthetic-instant-canary";
    let refusals = [
        shifted(canary, json!(0)),
        shifted("2026-10-09T09:00:00", json!(0)),
        shifted("2026-10-09", json!(0)),
        shifted("9999-12-31T23:59:59Z", json!(1)),
        shifted("0000-01-01T00:00:00Z", json!(-1)),
        shifted("2026-10-09T09:00:00Z", json!(9_007_199_254_740_991_i64)),
        shifted("2026-10-09T09:00:00Z", json!(-9_007_199_254_740_991_i64)),
        between(canary, "2026-10-09T09:00:00Z"),
        between("2026-10-09T09:00:00Z", "2026-10-09"),
    ];
    for refusal in refusals {
        let error = refusal.err().unwrap();
        assert_eq!(error.code, "function.execution");
        assert_eq!(error.message, REFUSED);
        let rendered = serde_json::to_string(&json!({
            "message": error.message, "field": error.field,
            "action": error.suggested_action, "diagnostics": format!("{:?}", error.diagnostics)
        }))
        .unwrap();
        assert!(!rendered.contains(canary), "{rendered}");
    }
    assert_eq!(
        shifted(canary, json!(0)).err().unwrap().field.as_deref(),
        Some("steps.due.waitUntil")
    );
    assert_eq!(
        between(canary, "2026-10-09T09:00:00Z")
            .err()
            .unwrap()
            .field
            .as_deref(),
        Some("steps.done.output")
    );
}

#[test]
fn the_function_profile_reads_no_clock() {
    let error = definition()
        .evaluate("clock", &json!({}), &BTreeMap::new())
        .err()
        .unwrap();
    assert_eq!(error.code, "function.execution");
}
