// SPDX-License-Identifier: Apache-2.0
//! JSON <-> Rhai conversion round-trips and bounds via the public API.

use registry_notary_source_adapter_rhai::convert::{dynamic_to_json, json_to_dynamic, ConvertCaps};
use registry_notary_source_adapter_rhai::SourceScriptError;
use serde_json::json;

fn caps() -> ConvertCaps {
    ConvertCaps {
        max_string_bytes: 1024,
        max_array_items: 256,
        max_map_entries: 256,
    }
}

#[test]
fn json_round_trip_is_lossless() {
    let original = json!([
        { "id": "a/p", "v": 42 },
        { "id": "b/q", "v": "hello" },
        { "id": "c/r", "v": [1, 2, 3], "nested": { "k": true }, "z": null }
    ]);
    let dynamic = json_to_dynamic(&original, caps()).unwrap();
    let back = dynamic_to_json(&dynamic, caps()).unwrap();
    assert_eq!(original, back);
}

#[test]
fn input_bounds_are_enforced() {
    let big_string = json!({ "s": "x".repeat(5000) });
    assert!(matches!(
        json_to_dynamic(&big_string, caps()).unwrap_err(),
        SourceScriptError::Type { .. }
    ));

    let big_array = json!((0..1000).collect::<Vec<i64>>());
    assert!(json_to_dynamic(&big_array, caps()).is_err());

    let mut m = serde_json::Map::new();
    for i in 0..1000 {
        m.insert(format!("k{i}"), json!(i));
    }
    assert!(json_to_dynamic(&serde_json::Value::Object(m), caps()).is_err());
}

#[test]
fn within_bounds_passes() {
    let ok = json!({ "s": "x".repeat(1000), "a": (0..200).collect::<Vec<i64>>() });
    assert!(json_to_dynamic(&ok, caps()).is_ok());
}
