// SPDX-License-Identifier: Apache-2.0
//! Validation of a script's return value.
//!
//! The contract for a source-adapter script is narrow: it must return an
//! **array of objects** of plain JSON scalars, capped at a small record count.
//! Field projection and downstream normalization happen elsewhere; this module
//! only enforces the structural shape so malformed output never escapes the
//! engine.

use serde_json::Value;

use crate::convert::MAX_JSON_DEPTH;
use crate::error::SourceScriptError;

/// The maximum number of records a script may return before normalization.
pub const MAX_RECORDS: usize = 100;

/// Validate a converted JSON return value and return it as a vector of records.
///
/// Rules:
/// * the top level must be an array;
/// * every item must be a JSON object;
/// * every object value must be a JSON scalar (null/bool/number/string), an
///   array of scalars, or a nested object of the same — i.e. plain data
///   (functions/opaque handles are already rejected at conversion time);
/// * at most [`MAX_RECORDS`] records.
pub fn validate_records(value: Value) -> Result<Vec<Value>, SourceScriptError> {
    let arr = match value {
        Value::Array(arr) => arr,
        other => {
            return Err(SourceScriptError::Type {
                detail: format!(
                    "script must return an array, got {}",
                    json_type_name(&other)
                ),
            });
        }
    };

    if arr.len() > MAX_RECORDS {
        return Err(SourceScriptError::Type {
            detail: format!("{} records exceeds maximum {}", arr.len(), MAX_RECORDS),
        });
    }

    for (idx, item) in arr.iter().enumerate() {
        match item {
            Value::Object(_) => check_data(item, 0).map_err(|detail| SourceScriptError::Type {
                detail: format!("record {idx}: {detail}"),
            })?,
            other => {
                return Err(SourceScriptError::Type {
                    detail: format!(
                        "record {idx} must be an object, got {}",
                        json_type_name(other)
                    ),
                });
            }
        }
    }

    Ok(arr)
}

/// Ensure a value is plain JSON data (no surprises). Since conversion already
/// rejects functions and opaque handles, this is a defensive structural check.
///
/// It is also depth-bounded: although `dynamic_to_json` already rejects an
/// over-depth value upstream, this validator recurses independently, so it
/// enforces the same [`MAX_JSON_DEPTH`] cap rather than trusting the caller.
fn check_data(value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!("nesting exceeds maximum depth {MAX_JSON_DEPTH}"));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
        Value::Array(arr) => {
            for v in arr {
                check_data(v, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for v in map.values() {
                check_data(v, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_array_of_objects() {
        let v = json!([{ "id": 1, "name": "a" }, { "id": 2, "name": "b" }]);
        let recs = validate_records(v).unwrap();
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn accepts_empty_array() {
        assert_eq!(validate_records(json!([])).unwrap().len(), 0);
    }

    #[test]
    fn accepts_nested_scalar_structures() {
        let v = json!([{ "tags": ["x", "y"], "meta": { "ok": true, "n": 3 } }]);
        assert!(validate_records(v).is_ok());
    }

    #[test]
    fn rejects_scalar_top_level() {
        assert!(matches!(
            validate_records(json!(42)).unwrap_err(),
            SourceScriptError::Type { .. }
        ));
        assert!(validate_records(json!("hi")).is_err());
        assert!(validate_records(json!(null)).is_err());
    }

    #[test]
    fn rejects_object_top_level() {
        assert!(validate_records(json!({ "a": 1 })).is_err());
    }

    #[test]
    fn rejects_non_object_item() {
        assert!(validate_records(json!([1, 2, 3])).is_err());
        assert!(validate_records(json!([{ "a": 1 }, "nope"])).is_err());
    }

    #[test]
    fn rejects_too_many_records() {
        let v: Vec<Value> = (0..MAX_RECORDS + 1).map(|i| json!({ "i": i })).collect();
        assert!(validate_records(Value::Array(v)).is_err());
        // Exactly the cap is allowed.
        let v: Vec<Value> = (0..MAX_RECORDS).map(|i| json!({ "i": i })).collect();
        assert!(validate_records(Value::Array(v)).is_ok());
    }

    #[test]
    fn rejects_record_nested_past_depth_cap() {
        // A single record whose value nests past the cap is rejected as a Type
        // error rather than overflowing the recursive validator.
        let mut deep = json!(0);
        for _ in 0..(MAX_JSON_DEPTH + 5) {
            deep = Value::Array(vec![deep]);
        }
        let v = Value::Array(vec![json!({ "deep": deep })]);
        assert!(matches!(
            validate_records(v).unwrap_err(),
            SourceScriptError::Type { .. }
        ));
    }
}
