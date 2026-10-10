// SPDX-License-Identifier: Apache-2.0
//! An explicit foreign JSON subtree keeps configuration refusals at its boundary.
mod common;

use common::{codes, decode, refusal};
use registry_platform_yaml::ForeignValue;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct ForeignDocument {
    value: ForeignValue,
    #[serde(default)]
    ordinary: Option<serde_json::Value>,
}

#[test]
fn foreign_json_nested_nulls_are_values_only_inside_the_explicit_subtree() {
    // An ordinary serde_json::Value member refuses null. Only the explicit
    // foreign subtree reads it, so ordinary configuration decoding stays strict.
    let report = refusal::<ForeignDocument>("value: {}\nordinary: {nested: [null]}\n");
    assert_eq!(codes(&report), ["config.null-value"]);
    assert_eq!(report.diagnostics()[0].path, "/ordinary/nested/0");
    for body in [
        "value: null\n",
        "value: {nested: [null, {also: null}], empty: []}\n",
    ] {
        let read: ForeignDocument = decode(body).unwrap();
        let expected = if body == "value: null\n" {
            serde_json::Value::Null
        } else {
            json!({"nested": [null, {"also": null}], "empty": []})
        };
        assert_eq!(read.value.as_value(), &expected);
        assert_eq!(serde_json::to_value(&read.value).unwrap(), expected);
        assert_eq!(read.value.into_value(), expected);
        assert!(read.ordinary.is_none());
    }
    let report = refusal::<ForeignDocument>("value: null\nordinary: null\n");
    assert_eq!(codes(&report), ["config.null-value"]);
    assert_eq!(report.diagnostics()[0].path, "/ordinary");
}

#[test]
fn foreign_json_cannot_bypass_structural_checks_or_hide_unknown_host_keys() {
    for (body, code) in [
        ("value: {a: null, a: 1}\n", "yaml.duplicate-key"),
        ("value: !!map {a: null}\n", "yaml.tag"),
        ("value: &node {a: null}\n", "yaml.anchor"),
        ("value: {a: *node}\n", "yaml.alias"),
        ("value: {true: null}\n", "yaml.non-string-key"),
        ("value: null\nextra: 1\n", "config.unknown-key"),
    ] {
        let report = refusal::<ForeignDocument>(body);
        assert!(codes(&report).contains(&code), "{report}");
    }
    let nested = format!("value: {}null{}\n", "[".repeat(130), "]".repeat(130));
    assert!(codes(&refusal::<ForeignDocument>(&nested)).contains(&"yaml.too-deep"));
}

#[cfg(feature = "schema")]
#[test]
fn foreign_json_schema_marks_the_explicit_foreign_boundary() {
    let schema = serde_json::to_value(schemars::schema_for!(ForeignValue)).unwrap();
    assert_eq!(schema["x-registry-foreign"], "json");
    assert!(schema.get("type").is_none());
}
