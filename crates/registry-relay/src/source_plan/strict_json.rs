// SPDX-License-Identifier: Apache-2.0
//! Structural JSON value decoding that preserves duplicate-member rejection.

use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

/// A JSON value decoded without erasing duplicate object members.
///
/// `serde_json::Value` cannot represent duplicate keys, so decoding directly
/// into it can hide ambiguity before a source codec or projection validates the
/// structure. This wrapper performs the recursive duplicate check first and is
/// intentionally neither cloneable nor debuggable.
pub(super) struct DuplicateFreeJsonValue(Value);

impl DuplicateFreeJsonValue {
    /// Consume the checked wrapper.
    pub(super) fn into_inner(self) -> Value {
        self.0
    }
}

impl<'de> Deserialize<'de> for DuplicateFreeJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateFreeJsonValueVisitor)
    }
}

struct DuplicateFreeJsonValueVisitor;

impl<'de> Visitor<'de> for DuplicateFreeJsonValueVisitor {
    type Value = DuplicateFreeJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(DuplicateFreeJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(DuplicateFreeJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateFreeJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DuplicateFreeJsonValue>()? {
            values.push(value.into_inner());
        }
        Ok(DuplicateFreeJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            let value = object.next_value::<DuplicateFreeJsonValue>()?;
            values.insert(key, value.into_inner());
        }
        Ok(DuplicateFreeJsonValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decode(raw: &str) -> Result<Value, serde_json::Error> {
        serde_json::from_str::<DuplicateFreeJsonValue>(raw).map(DuplicateFreeJsonValue::into_inner)
    }

    #[test]
    fn decodes_every_json_shape_without_exposing_a_debug_surface() {
        let value = decode(r#"{"z":[null,true,-1,2,3.5,"value"],"a":{"ok":false}}"#)
            .expect("duplicate-free fixture");
        assert_eq!(
            value,
            json!({"z": [null, true, -1, 2, 3.5, "value"], "a": {"ok": false}})
        );
    }

    #[test]
    fn rejects_duplicate_members_at_every_nested_position() {
        for raw in [
            r#"{"id":1,"id":2}"#,
            r#"{"outer":{"id":1,"id":2}}"#,
            r#"[{"id":1,"id":2}]"#,
            r#"{"items":[{"ok":1},{"id":1,"id":2}]}"#,
        ] {
            let error = decode(raw).expect_err("duplicate member rejected");
            assert!(error.to_string().contains("duplicate JSON object member"));
        }
    }
}
