// SPDX-License-Identifier: Apache-2.0
//! Bounded response decoding for the isolated source-adaptation worker.
//!
//! This is the one intentional general-value decoder for registry data. Its
//! output is admitted only to Relay's isolated script worker boundary. Raw
//! destination bytes remain inaccessible, JSON is strict, and code-owned
//! structural limits are applied before and after allocation.

use registry_platform_canonical_json::parse_json_strict;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::destination::{BoundedDestinationBody, DataDestinationBody};

use super::preflight::{preflight_json, JsonPreflightError};

/// Maximum nesting depth of JSON admitted to a source-adaptation script.
pub const MAX_SCRIPT_JSON_DEPTH: usize = 32;
/// Maximum aggregate JSON values admitted to a source-adaptation script.
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
    #[error("script source response is not valid UTF-8 text")]
    InvalidText,
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

/// UTF-8 text plus the encoded byte count consumed from the source budget.
pub struct ScriptTextResponse {
    value: Zeroizing<String>,
    encoded_bytes: usize,
}

impl ScriptTextResponse {
    #[must_use]
    pub fn into_parts(self) -> (Zeroizing<String>, usize) {
        (self.value, self.encoded_bytes)
    }
}

impl std::fmt::Debug for ScriptTextResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptTextResponse")
            .field("value", &"[REDACTED]")
            .field("encoded_bytes", &self.encoded_bytes)
            .finish()
    }
}

/// Consume an opaque destination body and release bounded strict JSON to the
/// isolated source-adaptation worker.
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

/// Decode caller-owned fixture bytes with the production Script JSON kernel.
///
/// This entry point exists so an offline fixture cannot accept a response
/// that the opaque production transport path would reject. It releases the
/// same bounded parsed value and never exposes transport-owned raw bytes.
pub fn decode_script_fixture_json(
    body: Vec<u8>,
) -> Result<ScriptJsonResponse, ScriptResponseDecodeError> {
    decode_script_json_bytes(Zeroizing::new(body))
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

/// Consume an opaque destination body and release bounded UTF-8 text to the
/// isolated source-adaptation worker.
pub fn decode_script_text(
    body: DataDestinationBody,
) -> Result<ScriptTextResponse, ScriptResponseDecodeError> {
    let BoundedDestinationBody { bytes, slot: _ } = body;
    decode_script_text_bytes(bytes)
}

/// Decode caller-owned fixture bytes with the production Script text kernel.
///
/// The one MiB code-owned text ceiling and UTF-8 validation are identical to
/// the opaque production transport path.
pub fn decode_script_fixture_text(
    body: Vec<u8>,
) -> Result<ScriptTextResponse, ScriptResponseDecodeError> {
    decode_script_text_bytes(Zeroizing::new(body))
}

fn decode_script_text_bytes(
    bytes: Zeroizing<Vec<u8>>,
) -> Result<ScriptTextResponse, ScriptResponseDecodeError> {
    let encoded_bytes = bytes.len();
    if bytes.len() > MAX_SCRIPT_JSON_STRING_BYTES {
        return Err(ScriptResponseDecodeError::StructuralLimitExceeded);
    }
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map(|value| ScriptTextResponse {
            value,
            encoded_bytes,
        })
        .map_err(|_| ScriptResponseDecodeError::InvalidText)
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

    #[test]
    fn decodes_bounded_text() {
        let (text, encoded_bytes) = decode_script_text(body("plain text")).unwrap().into_parts();
        assert_eq!(text.as_str(), "plain text");
        assert_eq!(encoded_bytes, 10);
        assert!(matches!(
            decode_script_text(body([0xff])),
            Err(ScriptResponseDecodeError::InvalidText)
        ));
    }

    #[test]
    fn production_and_fixture_json_paths_reject_the_same_semantic_limits() {
        let duplicate = br#"{"id":1,"id":2}"#;
        assert!(matches!(
            decode_script_json(body(duplicate)),
            Err(ScriptResponseDecodeError::InvalidJson)
        ));
        assert!(matches!(
            decode_script_fixture_json(duplicate.to_vec()),
            Err(ScriptResponseDecodeError::InvalidJson)
        ));

        let nested = format!(
            "{}0{}",
            "[".repeat(MAX_SCRIPT_JSON_DEPTH),
            "]".repeat(MAX_SCRIPT_JSON_DEPTH)
        );
        assert!(matches!(
            decode_script_json(body(&nested)),
            Err(ScriptResponseDecodeError::StructuralLimitExceeded)
        ));
        assert!(matches!(
            decode_script_fixture_json(nested.into_bytes()),
            Err(ScriptResponseDecodeError::StructuralLimitExceeded)
        ));
    }

    #[test]
    fn production_and_fixture_text_paths_reject_the_same_size_limit() {
        let oversized = vec![b'x'; MAX_SCRIPT_JSON_STRING_BYTES + 1];
        assert!(matches!(
            decode_script_text(body(&oversized)),
            Err(ScriptResponseDecodeError::StructuralLimitExceeded)
        ));
        assert!(matches!(
            decode_script_fixture_text(oversized),
            Err(ScriptResponseDecodeError::StructuralLimitExceeded)
        ));
    }
}
