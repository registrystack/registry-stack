// SPDX-License-Identifier: Apache-2.0
//! Bounded conversion between `serde_json::Value` and `rhai::Dynamic`.
//!
//! Input conversion (`json_to_dynamic`) is bounded by the configured string /
//! array / map caps so an oversized `ctx` cannot be smuggled in ahead of the
//! engine's own runtime limits.
//!
//! Output conversion (`dynamic_to_json`) additionally **rejects** any value
//! that is not pure data: function pointers, closures, and opaque host handles
//! all map to a [`SourceScriptError::Type`]. The script must return plain JSON.
//!
//! Both directions are **depth-bounded**. The size caps bound width but not
//! nesting depth; an adversarial script can build a structure thousands of
//! levels deep (`for i in 0..5000 { x = [x]; }`). Left unchecked, the recursive
//! validators below — and `rhai::serde::to_dynamic` / `serde_json::to_value`,
//! which also recurse — overflow the blocking thread's stack and *abort* the
//! process (uncatchable by the panic boundary). We therefore pre-walk the value
//! with an explicit depth counter and reject over-depth input *before* any
//! recursive serializer is invoked.

use rhai::Dynamic;
use serde_json::Value;

use crate::engine::RhaiLimits;
use crate::error::SourceScriptError;

/// Maximum nesting depth permitted for any value crossing the host boundary, in
/// either direction. Chosen well below the depth at which native recursion
/// (the validators here and Rhai/serde's own recursive (de)serializers) would
/// risk a stack overflow, while far exceeding any legitimate record shape.
pub const MAX_JSON_DEPTH: usize = 64;

/// Caps used while validating a converted value. Mirrors the engine's runtime
/// limits so input and output are held to the same shape constraints.
#[derive(Debug, Clone, Copy)]
pub struct ConvertCaps {
    /// Maximum length (UTF-8 bytes) of any single string.
    pub max_string_bytes: usize,
    /// Maximum number of items in any single array.
    pub max_array_items: usize,
    /// Maximum number of entries in any single map/object.
    pub max_map_entries: usize,
}

impl ConvertCaps {
    /// Derive caps from the engine limits.
    pub fn from_limits(limits: &RhaiLimits) -> Self {
        Self {
            max_string_bytes: limits.max_string_bytes,
            max_array_items: limits.max_array_items,
            max_map_entries: limits.max_map_entries,
        }
    }
}

/// Convert a JSON value into a Rhai `Dynamic`, enforcing the size and depth
/// caps.
///
/// The depth check runs **first**, before `rhai::serde::to_dynamic`, because
/// that conversion recurses and would overflow the stack on a hostile, deeply
/// nested input before any of our own checks could fire.
pub fn json_to_dynamic(value: &Value, caps: ConvertCaps) -> Result<Dynamic, SourceScriptError> {
    check_json_bounds(value, caps, 0)?;
    rhai::serde::to_dynamic(value.clone()).map_err(|e| SourceScriptError::Type {
        detail: format!("input conversion failed: {e}"),
    })
}

/// Convert a Rhai `Dynamic` into a JSON value, rejecting non-data values and
/// enforcing the size and depth caps.
///
/// Both `reject_non_data` and `serde_json::to_value` recurse, so the depth-
/// bounded `reject_non_data` walk runs **first** and rejects an over-depth
/// value before the serializer can overflow the stack.
pub fn dynamic_to_json(value: &Dynamic, caps: ConvertCaps) -> Result<Value, SourceScriptError> {
    reject_non_data(value, 0)?;
    let json = serde_json::to_value(value).map_err(|e| SourceScriptError::Type {
        detail: format!("output is not JSON-serializable: {e}"),
    })?;
    check_json_bounds(&json, caps, 0)?;
    Ok(json)
}

/// The error returned when a value nests deeper than [`MAX_JSON_DEPTH`].
fn depth_exceeded() -> SourceScriptError {
    SourceScriptError::Type {
        detail: format!("nesting exceeds maximum depth {MAX_JSON_DEPTH}"),
    }
}

/// Recursively reject function pointers, closures, and opaque host handles.
///
/// `serde_json::to_value` would already fail on a top-level `FnPtr`, but a
/// `FnPtr` nested inside an array/map can serialize in surprising ways across
/// Rhai versions; we walk the structure and reject explicitly so the contract
/// ("plain data only") does not depend on serializer behavior.
fn reject_non_data(value: &Dynamic, depth: usize) -> Result<(), SourceScriptError> {
    if depth > MAX_JSON_DEPTH {
        return Err(depth_exceeded());
    }
    if value.is::<rhai::FnPtr>() {
        return Err(SourceScriptError::Type {
            detail: "value contains a function/closure".into(),
        });
    }
    if let Some(arr) = value.read_lock::<rhai::Array>() {
        for item in arr.iter() {
            reject_non_data(item, depth + 1)?;
        }
        return Ok(());
    }
    if let Some(map) = value.read_lock::<rhai::Map>() {
        for item in map.values() {
            reject_non_data(item, depth + 1)?;
        }
        return Ok(());
    }
    // Permit the known scalar/data types. Anything else is treated as an opaque
    // host object and rejected.
    let ty = value.type_name();
    let is_known_data = value.is_unit()
        || value.is::<bool>()
        || value.is::<i64>()
        || value.is::<f64>()
        || value.is::<rhai::ImmutableString>()
        || value.is::<String>()
        || value.is::<char>();
    if !is_known_data {
        return Err(SourceScriptError::Type {
            detail: format!("value of opaque type `{ty}` is not allowed in output"),
        });
    }
    Ok(())
}

/// Enforce the string / array / map size caps and the depth cap recursively
/// over a JSON value. The depth check is performed before descending so a
/// hostile structure is rejected before native recursion can overflow.
fn check_json_bounds(
    value: &Value,
    caps: ConvertCaps,
    depth: usize,
) -> Result<(), SourceScriptError> {
    if depth > MAX_JSON_DEPTH {
        return Err(depth_exceeded());
    }
    match value {
        Value::String(s) => {
            if s.len() > caps.max_string_bytes {
                return Err(SourceScriptError::Type {
                    detail: format!(
                        "string of {} bytes exceeds cap {}",
                        s.len(),
                        caps.max_string_bytes
                    ),
                });
            }
        }
        Value::Array(arr) => {
            if arr.len() > caps.max_array_items {
                return Err(SourceScriptError::Type {
                    detail: format!(
                        "array of {} items exceeds cap {}",
                        arr.len(),
                        caps.max_array_items
                    ),
                });
            }
            for item in arr {
                check_json_bounds(item, caps, depth + 1)?;
            }
        }
        Value::Object(map) => {
            if map.len() > caps.max_map_entries {
                return Err(SourceScriptError::Type {
                    detail: format!(
                        "object of {} entries exceeds cap {}",
                        map.len(),
                        caps.max_map_entries
                    ),
                });
            }
            for v in map.values() {
                check_json_bounds(v, caps, depth + 1)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn caps() -> ConvertCaps {
        ConvertCaps {
            max_string_bytes: 1024,
            max_array_items: 256,
            max_map_entries: 256,
        }
    }

    #[test]
    fn round_trip_is_lossless() {
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
    fn round_trip_scalars() {
        for v in [json!(true), json!(0), json!(-7), json!("s"), json!(null)] {
            let d = json_to_dynamic(&v, caps()).unwrap();
            assert_eq!(dynamic_to_json(&d, caps()).unwrap(), v);
        }
    }

    #[test]
    fn input_string_cap_enforced() {
        let big = json!({ "s": "x".repeat(2000) });
        let e = json_to_dynamic(&big, caps()).unwrap_err();
        assert!(matches!(e, SourceScriptError::Type { .. }));
    }

    #[test]
    fn input_array_cap_enforced() {
        let big = json!((0..300).collect::<Vec<i64>>());
        assert!(json_to_dynamic(&big, caps()).is_err());
    }

    #[test]
    fn input_map_cap_enforced() {
        let mut m = serde_json::Map::new();
        for i in 0..300 {
            m.insert(format!("k{i}"), json!(i));
        }
        assert!(json_to_dynamic(&Value::Object(m), caps()).is_err());
    }

    #[test]
    fn output_rejects_function_pointer() {
        // A bare FnPtr as the value must be rejected by reject_non_data.
        let fnptr = Dynamic::from(rhai::FnPtr::new("foo").unwrap());
        let e = dynamic_to_json(&fnptr, caps()).unwrap_err();
        assert!(matches!(e, SourceScriptError::Type { .. }));
    }

    #[test]
    fn output_rejects_nested_function_pointer() {
        let arr: rhai::Array = vec![
            Dynamic::from(42_i64),
            Dynamic::from(rhai::FnPtr::new("foo").unwrap()),
        ];
        let d = Dynamic::from(arr);
        assert!(dynamic_to_json(&d, caps()).is_err());
    }

    /// Build a JSON value nested `depth` arrays deep around a scalar leaf.
    fn nested_json(depth: usize) -> Value {
        let mut v = json!(0);
        for _ in 0..depth {
            v = Value::Array(vec![v]);
        }
        v
    }

    /// Build a Rhai `Dynamic` nested `depth` arrays deep around a scalar leaf.
    fn nested_dynamic(depth: usize) -> Dynamic {
        let mut v = Dynamic::from(0_i64);
        for _ in 0..depth {
            let arr: rhai::Array = vec![v];
            v = Dynamic::from(arr);
        }
        v
    }

    #[test]
    fn input_depth_within_cap_is_accepted() {
        // At the cap (each level counts once) the value still converts.
        assert!(json_to_dynamic(&nested_json(MAX_JSON_DEPTH), caps()).is_ok());
    }

    #[test]
    fn input_depth_over_cap_is_rejected_as_type() {
        let e = json_to_dynamic(&nested_json(MAX_JSON_DEPTH + 5), caps()).unwrap_err();
        assert!(matches!(e, SourceScriptError::Type { .. }));
    }

    #[test]
    fn output_depth_over_cap_is_rejected_as_type() {
        let e = dynamic_to_json(&nested_dynamic(MAX_JSON_DEPTH + 5), caps()).unwrap_err();
        assert!(matches!(e, SourceScriptError::Type { .. }));
    }

    // A hostile depth (~5000) must be rejected by the explicit counter long
    // before native recursion (here, and inside the serde converters) could
    // overflow the stack. The whole point is that this returns an error rather
    // than aborting the test process.
    #[test]
    fn input_hostile_depth_rejected_without_abort() {
        let e = json_to_dynamic(&nested_json(5000), caps()).unwrap_err();
        assert!(matches!(e, SourceScriptError::Type { .. }));
    }

    #[test]
    fn output_hostile_depth_rejected_without_abort() {
        let e = dynamic_to_json(&nested_dynamic(5000), caps()).unwrap_err();
        assert!(matches!(e, SourceScriptError::Type { .. }));
    }
}
