// SPDX-License-Identifier: Apache-2.0
//! The schema of an id-keyed mapping states how many entries it may hold.

use registry_platform_yaml::{id_keyed_schema, id_keyed_schema_bounded, LocalId};
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::Value;

#[derive(JsonSchema)]
#[allow(dead_code)]
struct Entry {
    id: LocalId,
    title: String,
}

fn schema_of(bounded: Option<(u64, u64)>) -> Value {
    let mut generator = SchemaGenerator::default();
    match bounded {
        None => id_keyed_schema::<Entry>(&mut generator),
        Some((1, 256)) => id_keyed_schema_bounded::<Entry, 1, 256>(&mut generator),
        Some((0, 256)) => id_keyed_schema_bounded::<Entry, 0, 256>(&mut generator),
        Some(other) => panic!("not instantiated: {other:?}"),
    }
    .to_value()
}

#[test]
fn a_bounded_mapping_states_its_entry_counts() {
    let schema = schema_of(Some((1, 256)));
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["minProperties"], 1);
    assert_eq!(schema["maxProperties"], 256);
    assert!(schema["additionalProperties"]["properties"]["id"].is_null());
}

#[test]
fn a_zero_minimum_states_no_minimum() {
    let schema = schema_of(Some((0, 256)));
    assert!(schema.get("minProperties").is_none(), "{schema}");
    assert_eq!(schema["maxProperties"], 256);
}

#[test]
fn an_unbounded_mapping_states_no_counts() {
    let schema = schema_of(None);
    assert!(schema.get("minProperties").is_none(), "{schema}");
    assert!(schema.get("maxProperties").is_none(), "{schema}");
}
