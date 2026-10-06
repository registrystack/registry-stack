// SPDX-License-Identifier: Apache-2.0
//! Bounded response decoding for reviewed scripts.
//!
//! This is the one intentional general-value decoder for registry data. Its
//! output is admitted only to a reviewed script. Raw
//! destination bytes remain inaccessible, JSON is strict, and code-owned
//! structural limits are applied before and after allocation.

use registry_platform_canonical_json::parse_json_strict;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::destination::{BoundedDestinationBody, DataDestinationBody};

use super::preflight::{preflight_json, JsonPreflightError};

/// Maximum nesting depth of JSON admitted to a script.
pub const MAX_SCRIPT_JSON_DEPTH: usize = 32;
/// Maximum aggregate JSON values admitted to a script.
pub const MAX_SCRIPT_JSON_NODES: usize = 65_536;
/// Maximum members in any one JSON object admitted to a script.
pub const MAX_SCRIPT_JSON_OBJECT_MEMBERS: usize = 4_096;
/// Maximum items in any one JSON array admitted to a script.
pub const MAX_SCRIPT_JSON_ARRAY_ITEMS: usize = 16_384;
/// Maximum UTF-8 bytes in one JSON member name or String value.
pub const MAX_SCRIPT_JSON_STRING_BYTES: usize = 1_048_576;

/// Value-free failure while decoding one script-visible source response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScriptResponseDecodeError {
    #[error("script source response is not strict JSON")]
    InvalidJson,
    #[error("script source response exceeds a code-owned structural limit")]
    StructuralLimitExceeded,
}

/// Strict JSON plus the encoded byte count consumed from the source budget.
pub struct ScriptJsonResponse {
    value: Value,
    encoded_bytes: usize,
}

impl ScriptJsonResponse {
    #[must_use]
    pub fn into_parts(self) -> (Value, usize) {
        (self.value, self.encoded_bytes)
    }
}

impl std::fmt::Debug for ScriptJsonResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptJsonResponse")
            .field("value", &"[REDACTED]")
            .field("encoded_bytes", &self.encoded_bytes)
            .finish()
    }
}

/// Consume an opaque destination body and release bounded strict JSON to a
/// reviewed script.
///
/// Callers must also enforce the authored per-response and aggregate byte
/// limits before invoking this decoder. This function enforces code-owned
/// parser and in-memory shape ceilings independent of those authored limits.
pub fn decode_script_json(
    body: DataDestinationBody,
) -> Result<ScriptJsonResponse, ScriptResponseDecodeError> {
    let BoundedDestinationBody { bytes, slot: _ } = body;
    decode_script_json_bytes(bytes)
}

fn decode_script_json_bytes(
    bytes: Zeroizing<Vec<u8>>,
) -> Result<ScriptJsonResponse, ScriptResponseDecodeError> {
    let encoded_bytes = bytes.len();
    preflight_json(
        bytes.as_slice(),
        MAX_SCRIPT_JSON_NODES,
        MAX_SCRIPT_JSON_DEPTH,
    )
    .map_err(|error| match error {
        JsonPreflightError::InvalidJson => ScriptResponseDecodeError::InvalidJson,
        JsonPreflightError::ContractLimitExceeded => {
            ScriptResponseDecodeError::StructuralLimitExceeded
        }
    })?;
    let parsed =
        parse_json_strict(bytes.as_slice()).map_err(|_| ScriptResponseDecodeError::InvalidJson)?;
    drop(bytes);
    validate_shape(&parsed, 1, &mut 0)?;
    Ok(ScriptJsonResponse {
        value: parsed,
        encoded_bytes,
    })
}

fn validate_shape(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ScriptResponseDecodeError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(ScriptResponseDecodeError::StructuralLimitExceeded)?;
    if *nodes > MAX_SCRIPT_JSON_NODES || depth > MAX_SCRIPT_JSON_DEPTH {
        return Err(ScriptResponseDecodeError::StructuralLimitExceeded);
    }
    match value {
        Value::String(value) => validate_string(value),
        Value::Array(values) => {
            if values.len() > MAX_SCRIPT_JSON_ARRAY_ITEMS {
                return Err(ScriptResponseDecodeError::StructuralLimitExceeded);
            }
            for value in values {
                validate_shape(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_SCRIPT_JSON_OBJECT_MEMBERS {
                return Err(ScriptResponseDecodeError::StructuralLimitExceeded);
            }
            for (name, value) in values {
                validate_string(name)?;
                validate_shape(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_string(value: &str) -> Result<(), ScriptResponseDecodeError> {
    (value.len() <= MAX_SCRIPT_JSON_STRING_BYTES)
        .then_some(())
        .ok_or(ScriptResponseDecodeError::StructuralLimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::marker::PhantomData;

    fn body(raw: impl AsRef<[u8]>) -> DataDestinationBody {
        BoundedDestinationBody {
            bytes: Zeroizing::new(raw.as_ref().to_vec()),
            slot: PhantomData,
        }
    }

    #[test]
    fn decodes_strict_bounded_json() {
        let decoded = decode_script_json(body(br#"{"records":[{"id":"one"}]}"#)).unwrap();
        let (value, encoded_bytes) = decoded.into_parts();
        assert_eq!(value, serde_json::json!({"records":[{"id":"one"}]}));
        assert_eq!(encoded_bytes, 26);
        assert!(matches!(
            decode_script_json(body(br#"{"id":1,"id":2}"#)),
            Err(ScriptResponseDecodeError::InvalidJson)
        ));
    }

    #[test]
    fn rejects_shape_beyond_code_owned_limits() {
        let nested = format!(
            "{}0{}",
            "[".repeat(MAX_SCRIPT_JSON_DEPTH),
            "]".repeat(MAX_SCRIPT_JSON_DEPTH)
        );
        assert!(matches!(
            decode_script_json(body(nested)),
            Err(ScriptResponseDecodeError::StructuralLimitExceeded)
        ));
    }
}
