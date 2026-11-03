// SPDX-License-Identifier: Apache-2.0

//! Source-neutral recursive JSON field-bound enforcement.

/// Whether every string and object member name in one JSON value is within
/// the configured field bound. Serde JSON's parser nesting limit bounds this
/// recursive walk.
#[cfg_attr(
    not(any(feature = "job-file", feature = "job-rabbitmq")),
    allow(dead_code)
)]
pub(crate) fn json_within_field_bound(
    value: &serde_json::Value,
    maximum_field_bytes: usize,
) -> bool {
    match value {
        serde_json::Value::String(text) => text.len() <= maximum_field_bytes,
        serde_json::Value::Array(values) => values
            .iter()
            .all(|value| json_within_field_bound(value, maximum_field_bytes)),
        serde_json::Value::Object(members) => members.iter().all(|(name, value)| {
            name.len() <= maximum_field_bytes && json_within_field_bound(value, maximum_field_bytes)
        }),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => true,
    }
}
