// SPDX-License-Identifier: Apache-2.0
//! Duplicate-JSON-member rejection.
//!
//! Structured values that cross the byte-transfer outcome boundary must not
//! carry two members with the same name: re-parsing with
//! `serde_json::from_slice` would silently keep the last one. This module
//! parses bytes into a `serde_json::Value` while rejecting any object that
//! repeats a member, at any depth, using a `DeserializeSeed`/`Visitor` walk
//! so the stream is read exactly once. Content after the first JSON value is
//! refused: the bytes hold exactly one document, not one document plus
//! whatever follows it.
//!
//! The check is engine-neutral: it guards JSON bytes, whatever backend
//! produced them. It is compiled under the `wasm` feature alongside the
//! byte-transfer ABI it serves today.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Path segments and member names carried in errors are bounded so a
/// hostile document cannot balloon the error text.
const PATH_LIMIT: usize = 128;
const MEMBER_LIMIT: usize = 64;

/// The parse failed: either a repeated object member was found, or the
/// bytes were not JSON at all. The payload is host-generated and bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateMemberError {
    kind: ErrorKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ErrorKind {
    Duplicate { path: String, member: String },
    Malformed { detail: String },
}

impl DuplicateMemberError {
    /// The JSON-pointer-style path of the object that repeated a member,
    /// e.g. `$.effects[0].set`.
    pub fn duplicate_path(&self) -> Option<&str> {
        match &self.kind {
            ErrorKind::Duplicate { path, .. } => Some(path),
            ErrorKind::Malformed { .. } => None,
        }
    }

    fn duplicate(path: String, member: String) -> Self {
        Self {
            kind: ErrorKind::Duplicate { path, member },
        }
    }

    fn malformed(detail: String) -> Self {
        Self {
            kind: ErrorKind::Malformed { detail },
        }
    }
}

impl fmt::Display for DuplicateMemberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Duplicate { path, member } => {
                write!(f, "duplicate JSON member \"{member}\" in object at {path}")
            }
            ErrorKind::Malformed { detail } => write!(f, "not valid JSON: {detail}"),
        }
    }
}

impl std::error::Error for DuplicateMemberError {}

/// Parse `bytes` into a `Value`, rejecting any object that repeats a member
/// (recursing through nested objects and arrays) and refusing anything other
/// than whitespace after the first JSON value: the outcome contract is
/// exactly one document.
pub fn check_no_duplicate_members(bytes: &[u8]) -> Result<Value, DuplicateMemberError> {
    // The error slot outlives the deserializer borrow, so the typed error
    // survives even though serde_json only reports `de::Error`.
    let error: Rc<RefCell<Option<DuplicateMemberError>>> = Rc::new(RefCell::new(None));
    let visitor = NoDuplicateVisitor {
        path: "$".to_owned(),
        error: Rc::clone(&error),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = serde::Deserializer::deserialize_any(&mut deserializer, visitor);
    match result {
        Ok(value) => deserializer
            .end()
            .map(|()| value)
            .map_err(|err| DuplicateMemberError::malformed(bounded(&err.to_string(), 256))),
        Err(err) => Err(error
            .borrow_mut()
            .take()
            .unwrap_or_else(|| DuplicateMemberError::malformed(bounded(&err.to_string(), 256)))),
    }
}

fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Seed carried at each nesting level: the path prefix and the shared error
/// slot.
struct NoDuplicateSeed {
    path: String,
    error: Rc<RefCell<Option<DuplicateMemberError>>>,
}

impl<'de> DeserializeSeed<'de> for NoDuplicateSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor {
            path: self.path,
            error: self.error,
        })
    }
}

struct NoDuplicateVisitor {
    path: String,
    error: Rc<RefCell<Option<DuplicateMemberError>>>,
}

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                let duplicate = DuplicateMemberError::duplicate(
                    bounded(&self.path, PATH_LIMIT),
                    bounded(&key, MEMBER_LIMIT),
                );
                // Remember the typed error, then abort the stream read; the
                // outer wrapper picks it up from the slot.
                *self.error.borrow_mut() = Some(duplicate);
                return Err(de::Error::custom("duplicate JSON member"));
            }
            let child = NoDuplicateSeed {
                path: format!(
                    "{}.{}",
                    bounded(&self.path, PATH_LIMIT),
                    bounded(&key, MEMBER_LIMIT)
                ),
                error: Rc::clone(&self.error),
            };
            let value = access.next_value_seed(child)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        let mut index = 0usize;
        while let Some(value) = access.next_element_seed(NoDuplicateSeed {
            path: format!("{}[{index}]", bounded(&self.path, PATH_LIMIT)),
            error: Rc::clone(&self.error),
        })? {
            items.push(value);
            index += 1;
        }
        Ok(Value::Array(items))
    }

    // Scalars delegate to serde_json's own Value visitor.

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor {
            path: self.path,
            error: self.error,
        })
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::check_no_duplicate_members;
    use serde_json::json;

    #[test]
    fn top_level_duplicate_is_rejected_with_the_member_and_path() {
        let err = check_no_duplicate_members(br#"{"a": 1, "b": 2, "a": 3}"#).unwrap_err();
        assert_eq!(err.duplicate_path(), Some("$"));
        assert_eq!(
            err.to_string(),
            "duplicate JSON member \"a\" in object at $"
        );
    }

    #[test]
    fn nested_duplicate_is_rejected_with_the_nested_path() {
        let err = check_no_duplicate_members(br#"{"outer": {"x": 1, "x": 2}}"#).unwrap_err();
        assert_eq!(err.duplicate_path(), Some("$.outer"));
    }

    #[test]
    fn duplicate_inside_an_array_element_is_rejected() {
        let err = check_no_duplicate_members(br#"{"effects": [{"id": 1, "id": 2}]}"#).unwrap_err();
        assert_eq!(err.duplicate_path(), Some("$.effects[0]"));
    }

    #[test]
    fn distinct_keys_at_every_depth_pass_and_match_from_slice() {
        let bytes = br#"{"a": 1, "b": {"c": [1, 2, {"d": null}]}, "e": "s"}"#;
        let checked = check_no_duplicate_members(bytes).expect("no duplicates");
        assert_eq!(
            checked,
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap()
        );
    }

    #[test]
    fn member_order_is_irrelevant() {
        let checked = check_no_duplicate_members(br#"{"a": 1, "b": 2}"#).unwrap();
        let reordered = check_no_duplicate_members(br#"{"b": 2, "a": 1}"#).unwrap();
        assert_eq!(checked, reordered);
    }

    #[test]
    fn non_object_json_passes() {
        assert_eq!(check_no_duplicate_members(b"42").unwrap(), json!(42));
        assert_eq!(
            check_no_duplicate_members(b"[1,2,3]").unwrap(),
            json!([1, 2, 3])
        );
        assert_eq!(
            check_no_duplicate_members(b"[1,[2,{\"k\":2}]]").unwrap(),
            json!([1, [2, {"k": 2}]])
        );
        assert_eq!(
            check_no_duplicate_members(br#""text""#).unwrap(),
            json!("text")
        );
        assert_eq!(check_no_duplicate_members(b"null").unwrap(), json!(null));
        assert_eq!(check_no_duplicate_members(b"true").unwrap(), json!(true));
    }

    #[test]
    fn malformed_json_is_reported_as_malformed() {
        let err = check_no_duplicate_members(br#"{"a": "#).unwrap_err();
        assert_eq!(err.duplicate_path(), None);
        assert!(err.to_string().starts_with("not valid JSON"), "{}", err);
    }

    #[test]
    fn trailing_content_after_the_document_is_rejected() {
        for bytes in [
            br#"{"a": 1} garbage"#.as_slice(),
            br#"{"a": 1}}"#.as_slice(),
            br#"{"a": 1} {"b": 2}"#.as_slice(),
            b"1 2".as_slice(),
        ] {
            let err = check_no_duplicate_members(bytes).unwrap_err();
            assert_eq!(err.duplicate_path(), None, "{bytes:?}");
            assert!(
                err.to_string().starts_with("not valid JSON"),
                "{bytes:?}: {err}"
            );
        }
    }

    #[test]
    fn trailing_whitespace_after_the_document_is_accepted() {
        assert_eq!(
            check_no_duplicate_members(b"{\"a\": 1}\n\t \r\n").unwrap(),
            json!({"a": 1})
        );
        assert_eq!(check_no_duplicate_members(b"42 \n").unwrap(), json!(42));
    }

    #[test]
    fn a_single_document_with_no_trailing_bytes_is_accepted() {
        assert_eq!(
            check_no_duplicate_members(br#"{"a": 1, "b": [true, null]}"#).unwrap(),
            json!({"a": 1, "b": [true, null]})
        );
        assert_eq!(check_no_duplicate_members(b"true").unwrap(), json!(true));
    }
}
