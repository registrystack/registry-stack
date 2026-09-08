// SPDX-License-Identifier: Apache-2.0
//! Inert logical record references shared by authored fixtures and local examples.
//!
//! This module performs no I/O and grants no fixture receipt authority. Callers
//! validate capture entity types against the owning field contract before use.
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("logical record reference is malformed, unavailable or exceeds its nesting bound")]
pub struct ReferenceError;

/// Recognize the existing exact `{ "recordRef": "alias" }` authored form.
pub fn record_reference(value: &Value) -> Result<Option<&str>, ReferenceError> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(reference) = object.get("recordRef") else {
        return Ok(None);
    };
    let reference = reference.as_str().ok_or(ReferenceError)?;
    if object.len() != 1
        || reference.is_empty()
        || reference.len() > 64
        || !reference.as_bytes()[0].is_ascii_lowercase()
        || !reference
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(ReferenceError);
    }
    Ok(Some(reference))
}

/// Resolve bounded logical aliases into identifiers already validated by the
/// caller. Missing or future captures are refused; no identifier is fabricated.
pub fn resolve_record_references(
    value: &Value,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Value, ReferenceError> {
    fn resolve(
        value: &Value,
        lookup: &impl Fn(&str) -> Option<String>,
        depth: usize,
    ) -> Result<Value, ReferenceError> {
        if depth > 32 {
            return Err(ReferenceError);
        }
        if let Some(alias) = record_reference(value)? {
            return lookup(alias).map(Value::String).ok_or(ReferenceError);
        }
        match value {
            Value::Object(object) => object
                .iter()
                .map(|(k, v)| Ok((k.clone(), resolve(v, lookup, depth + 1)?)))
                .collect::<Result<_, _>>()
                .map(Value::Object),
            Value::Array(values) => values
                .iter()
                .map(|v| resolve(v, lookup, depth + 1))
                .collect::<Result<_, _>>()
                .map(Value::Array),
            _ => Ok(value.clone()),
        }
    }
    resolve(value, &lookup, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn shared_grammar_resolves_nested_aliases_and_refuses_malformed_or_unavailable_captures() {
        let value = json!({"items":[{"recordRef":"first"},null,5]});
        assert_eq!(
            resolve_record_references(&value, |id| (id == "first").then(|| "returned-id".into()))
                .unwrap(),
            json!({"items":["returned-id",null,5]})
        );
        for value in [
            json!({"recordRef":"missing"}),
            json!({"recordRef":3}),
            json!({"recordRef":"first","other":true}),
            json!({"recordRef":"../first"}),
        ] {
            assert!(resolve_record_references(&value, |_| None).is_err());
        }
        let nested = (0..34).fold(json!(null), |v, _| json!([v]));
        assert!(resolve_record_references(&nested, |_| None).is_err());
    }
}
