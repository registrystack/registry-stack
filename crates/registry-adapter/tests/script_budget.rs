// SPDX-License-Identifier: Apache-2.0

//! The script budget: a script handed a reply as large as the runtime
//! accepts is processed, and a script that loops or builds without end still
//! ends in a budget failure.

use registry_adapter::scripts::{ScriptFailure, ScriptSet};
use registry_adapter_core::AdapterPack;
use registry_platform_config::sha256_uri;
use serde_json::{json, Value};

/// The runtime's reply cap (`MAXIMUM_RESPONSE_BYTES` in `load.rs`).
const REPLY_CAP: usize = 1024 * 1024;

fn set_with(source: &str) -> ScriptSet {
    let directory = tempfile::tempdir().expect("a scratch directory");
    std::fs::write(directory.path().join("probe.rhai"), source).expect("the script is written");
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "probe",
        "version": "1",
        "testedVersions": ["1"],
        "scripts": [{"path": "probe.rhai", "digest": sha256_uri(source.as_bytes())}],
    }))
    .expect("the pack parses");
    let mut set = ScriptSet::default();
    set.add(&pack, directory.path(), "probe.rhai", "probe")
        .expect("the script compiles under its pinned digest");
    set
}

fn exchange(body: Value) -> Value {
    json!({"body": body, "headers": {}, "properties": {}})
}

#[test]
fn a_reply_at_the_cap_is_processed() {
    let set = set_with("fn probe(exchange) { exchange.body.len() }");

    let text = "x".repeat(REPLY_CAP);
    let size = set.call("probe.rhai", "probe", &exchange(json!(text)));

    assert_eq!(size.expect("processed"), json!(REPLY_CAP));
}

#[test]
fn a_reply_of_many_small_rows_is_walked_to_the_end() {
    let set = set_with(
        "fn probe(exchange) { let n = 0; for row in exchange.body.rows { n += row.len(); } n }",
    );
    // Two bytes per item is the densest array a reply of this size can hold.
    let rows: Vec<Value> = (0..REPLY_CAP / 2).map(|_| json!(1)).collect();
    let entries: serde_json::Map<String, Value> = (0..REPLY_CAP / 8)
        .map(|index| (format!("k{index}"), json!(1)))
        .collect();

    let walked = set.call(
        "probe.rhai",
        "probe",
        &exchange(json!({"rows": [json!(entries)], "dense": rows})),
    );

    assert!(walked.is_ok(), "{walked:?}");
}

#[test]
fn a_loop_without_end_is_a_budget_failure() {
    let set = set_with("fn probe(exchange) { let n = 0; loop { n += 1; } }");

    let failure = set.call("probe.rhai", "probe", &exchange(json!({})));

    assert!(matches!(failure, Err(ScriptFailure::Budget)), "{failure:?}");
}

#[test]
fn a_string_that_doubles_without_end_is_a_budget_failure() {
    let set = set_with(r#"fn probe(exchange) { let s = "x"; loop { s += s; } }"#);

    let failure = set.call("probe.rhai", "probe", &exchange(json!({})));

    assert!(matches!(failure, Err(ScriptFailure::Budget)), "{failure:?}");
}

#[test]
fn an_array_that_grows_without_end_is_a_budget_failure() {
    let set = set_with("fn probe(exchange) { let a = []; loop { a.push(1); } }");

    let failure = set.call("probe.rhai", "probe", &exchange(json!({})));

    assert!(matches!(failure, Err(ScriptFailure::Budget)), "{failure:?}");
}
