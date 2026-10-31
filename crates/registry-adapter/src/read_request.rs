// SPDX-License-Identifier: Apache-2.0

//! The request template of a read over POST, and the typed filters a read
//! carries. The template is the operation's request envelope read as a
//! closed shape over the caller's JSON body: a literal must equal the
//! body's value, and a slot captures one request input (`recordId`,
//! `filters`, `pageSize`, `cursor`). A body that does not have the
//! template's shape is a shape fault (`facade.invalid-request`); a body of
//! the right shape whose literal differs, whose filter is undeclared, or
//! whose value fails its declared type is a field fault
//! (`facade.invalid-field`). Reasons are value-free: they name where the
//! fault is, never what the caller sent.

use std::collections::BTreeSet;

use registry_adapter_core::{
    decode_slot, is_date, is_date_time, parse_envelope_template, RecordFieldType, SlotForm,
    READ_REQUEST_SLOTS,
};
use serde_json::{Map, Number, Value};

/// A filter one binding declares: the record field it names and that
/// field's type.
#[derive(Clone, Debug)]
pub struct ServedFilter {
    pub name: String,
    pub field_type: RecordFieldType,
}

#[derive(Clone, Debug)]
enum Node {
    Literal(Value),
    Slot { name: String, optional: bool },
    Object(Vec<(String, Node)>),
    Array(Vec<Node>),
}

/// A read's request envelope compiled for matching.
#[derive(Clone, Debug)]
pub struct ReadRequestTemplate(Node);

/// Why a body was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadRefusal {
    /// The body is not the template's shape: `facade.invalid-request`.
    Shape(String),
    /// The body has the shape, but a value is refused:
    /// `facade.invalid-field`.
    Field(String),
}

/// What the template's slots captured from one body.
#[derive(Debug, Default, PartialEq)]
pub struct Captured {
    pub record_id: Option<String>,
    pub filters: Option<Map<String, Value>>,
    pub page_size: Option<u64>,
    pub cursor: Option<String>,
}

impl ReadRequestTemplate {
    /// Compile `text`.
    ///
    /// # Errors
    ///
    /// A value-free account of why the template cannot be matched: it is
    /// not a template, names a slot a read's body does not fill, repeats a
    /// slot, or places an optional slot where it fills no object member.
    pub fn compile(text: &str) -> Result<Self, String> {
        let parsed = parse_envelope_template(text)?;
        let mut seen = BTreeSet::new();
        let node = node(&parsed, &mut seen)?;
        Ok(Self(node))
    }

    /// Whether the template names the slot.
    #[must_use]
    pub fn names(&self, slot: &str) -> bool {
        fn walk(node: &Node, slot: &str) -> bool {
            match node {
                Node::Slot { name, .. } => name == slot,
                Node::Literal(_) => false,
                Node::Object(members) => members.iter().any(|(_, member)| walk(member, slot)),
                Node::Array(items) => items.iter().any(|item| walk(item, slot)),
            }
        }
        walk(&self.0, slot)
    }

    /// Match `body` against the template, capturing what its slots name.
    /// `filters` is the binding's declared filter set; a captured filters
    /// object is checked against it.
    ///
    /// # Errors
    ///
    /// A [`ReadRefusal`] naming the member that failed, value-free.
    pub fn capture(&self, body: &Value, filters: &[ServedFilter]) -> Result<Captured, ReadRefusal> {
        let mut captured = Captured::default();
        matches_node(&self.0, body, "", filters, &mut captured)?;
        Ok(captured)
    }
}

fn node(template: &Value, seen: &mut BTreeSet<String>) -> Result<Node, String> {
    match template {
        Value::String(text) => match decode_slot(text) {
            Some((name, form)) => {
                if !READ_REQUEST_SLOTS.contains(&name) {
                    return Err(format!(
                        "the request envelope names slot {name}, which a read's body does not fill"
                    ));
                }
                if !seen.insert(name.to_owned()) {
                    return Err(format!("the request envelope names slot {name} twice"));
                }
                Ok(Node::Slot {
                    name: name.to_owned(),
                    optional: form != SlotForm::Required,
                })
            }
            None => Ok(Node::Literal(template.clone())),
        },
        Value::Object(members) => {
            let mut compiled = Vec::with_capacity(members.len());
            for (key, member) in members {
                compiled.push((key.clone(), node(member, seen)?));
            }
            Ok(Node::Object(compiled))
        }
        Value::Array(items) => {
            let compiled = items
                .iter()
                .map(|item| node(item, seen))
                .collect::<Result<Vec<_>, _>>()?;
            if compiled
                .iter()
                .any(|item| matches!(item, Node::Slot { optional: true, .. }))
            {
                return Err(
                    "an optional slot fills an object member, never an array item".to_owned(),
                );
            }
            Ok(Node::Array(compiled))
        }
        other => Ok(Node::Literal(other.clone())),
    }
}

fn shape(at: &str, fault: &str) -> ReadRefusal {
    ReadRefusal::Shape(format!("{fault} at {}", pointer(at)))
}

fn field(at: &str, fault: &str) -> ReadRefusal {
    ReadRefusal::Field(format!("{fault} at {}", pointer(at)))
}

fn pointer(at: &str) -> &str {
    if at.is_empty() {
        "the body root"
    } else {
        at
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn matches_node(
    node: &Node,
    body: &Value,
    at: &str,
    filters: &[ServedFilter],
    captured: &mut Captured,
) -> Result<(), ReadRefusal> {
    match node {
        Node::Literal(literal) => {
            if type_name(literal) != type_name(body) {
                return Err(shape(at, "the member has the wrong JSON type"));
            }
            if literal != body {
                return Err(field(
                    at,
                    "the member differs from the value the contract fixes",
                ));
            }
            Ok(())
        }
        Node::Slot { name, .. } => capture_slot(name, body, at, filters, captured),
        Node::Object(members) => {
            let Value::Object(map) = body else {
                return Err(shape(at, "the member is not an object"));
            };
            // A member's name is the caller's text; only the object's place
            // is reported.
            if map
                .keys()
                .any(|key| !members.iter().any(|(name, _)| name == key))
            {
                return Err(shape(
                    at,
                    "the object carries a member the contract does not declare",
                ));
            }
            for (key, member) in members {
                let member_at = format!("{at}/{key}");
                match map.get(key) {
                    Some(value) => matches_node(member, value, &member_at, filters, captured)?,
                    None if matches!(member, Node::Slot { optional: true, .. }) => {}
                    None => return Err(shape(&member_at, "the member is missing")),
                }
            }
            Ok(())
        }
        Node::Array(items) => {
            let Value::Array(values) = body else {
                return Err(shape(at, "the member is not an array"));
            };
            if values.len() != items.len() {
                return Err(shape(at, "the array has the wrong length"));
            }
            for (index, (item, value)) in items.iter().zip(values).enumerate() {
                matches_node(item, value, &format!("{at}/{index}"), filters, captured)?;
            }
            Ok(())
        }
    }
}

fn capture_slot(
    name: &str,
    body: &Value,
    at: &str,
    filters: &[ServedFilter],
    captured: &mut Captured,
) -> Result<(), ReadRefusal> {
    match name {
        "recordId" => {
            let Value::String(id) = body else {
                return Err(shape(at, "the member is not a string"));
            };
            if id.is_empty() {
                return Err(field(at, "the identifier is empty"));
            }
            captured.record_id = Some(id.clone());
        }
        "cursor" => {
            let Value::String(cursor) = body else {
                return Err(shape(at, "the member is not a string"));
            };
            captured.cursor = Some(cursor.clone());
        }
        "pageSize" => {
            let size = body
                .as_u64()
                .ok_or_else(|| shape(at, "the member is not a non-negative integer"))?;
            captured.page_size = Some(size);
        }
        "filters" => {
            let Value::Object(map) = body else {
                return Err(shape(at, "the member is not an object"));
            };
            for (key, value) in map {
                let declared = filters
                    .iter()
                    .find(|filter| &filter.name == key)
                    .ok_or_else(|| {
                        field(at, "the object names a filter the binding does not declare")
                    })?;
                if !value_has_type(value, declared.field_type) {
                    return Err(field(
                        &format!("{at}/{}", declared.name),
                        "the value does not have the filter's declared type",
                    ));
                }
            }
            captured.filters = Some(map.clone());
        }
        other => unreachable!("slot {other} was refused at compile"),
    }
    Ok(())
}

/// Whether a JSON value has the declared type of a record field.
fn value_has_type(value: &Value, field_type: RecordFieldType) -> bool {
    match (field_type, value) {
        (RecordFieldType::String, Value::String(_))
        | (RecordFieldType::Boolean, Value::Bool(_))
        | (RecordFieldType::Decimal, Value::Number(_)) => true,
        (RecordFieldType::Integer, Value::Number(number)) => number.is_i64() || number.is_u64(),
        (RecordFieldType::Date, Value::String(text)) => is_date(text),
        (RecordFieldType::DateTime, Value::String(text)) => is_date_time(text),
        _ => false,
    }
}

/// Parse one declared filter's query-string value into its declared type,
/// or `None` when the text is not a value of that type.
#[must_use]
pub fn parse_filter_text(text: &str, field_type: RecordFieldType) -> Option<Value> {
    match field_type {
        RecordFieldType::String => Some(Value::String(text.to_owned())),
        RecordFieldType::Integer => text
            .parse::<i64>()
            .ok()
            .map(|number| Value::Number(Number::from(number))),
        RecordFieldType::Decimal => text
            .parse::<f64>()
            .ok()
            .filter(|number| number.is_finite())
            .and_then(Number::from_f64)
            .map(Value::Number),
        RecordFieldType::Boolean => match text {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        RecordFieldType::Date => is_date(text).then(|| Value::String(text.to_owned())),
        RecordFieldType::DateTime => is_date_time(text).then(|| Value::String(text.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn filters() -> Vec<ServedFilter> {
        vec![
            ServedFilter {
                name: "org_unit".to_owned(),
                field_type: RecordFieldType::String,
            },
            ServedFilter {
                name: "born".to_owned(),
                field_type: RecordFieldType::Date,
            },
            ServedFilter {
                name: "count".to_owned(),
                field_type: RecordFieldType::Integer,
            },
        ]
    }

    fn lookup() -> ReadRequestTemplate {
        ReadRequestTemplate::compile(r#"{"selector": "byId", "values": {"id": "{{recordId}}"}}"#)
            .expect("a lookup template")
    }

    fn search() -> ReadRequestTemplate {
        ReadRequestTemplate::compile(
            r#"{"filters": "{{filters}}", "pageSize": "{{?pageSize}}", "cursor": "{{?cursor}}"}"#,
        )
        .expect("a search template")
    }

    #[test]
    fn a_lookup_body_fills_the_record_identifier() {
        let captured = lookup()
            .capture(
                &json!({"selector": "byId", "values": {"id": "abc"}}),
                &filters(),
            )
            .expect("matches");
        assert_eq!(captured.record_id.as_deref(), Some("abc"));
    }

    #[test]
    fn a_wrong_shape_is_a_shape_fault() {
        for body in [
            json!([]),
            json!({"selector": "byId"}),
            json!({"selector": "byId", "values": {"id": 7}}),
            json!({"selector": "byId", "values": {"id": "a"}, "extra": 1}),
            json!({"selector": 3, "values": {"id": "a"}}),
        ] {
            assert!(
                matches!(
                    lookup().capture(&body, &filters()),
                    Err(ReadRefusal::Shape(_))
                ),
                "{body}"
            );
        }
    }

    #[test]
    fn a_literal_mismatch_or_empty_identifier_is_a_field_fault() {
        for body in [
            json!({"selector": "other", "values": {"id": "a"}}),
            json!({"selector": "byId", "values": {"id": ""}}),
        ] {
            assert!(
                matches!(
                    lookup().capture(&body, &filters()),
                    Err(ReadRefusal::Field(_))
                ),
                "{body}"
            );
        }
    }

    #[test]
    fn filters_are_checked_against_the_declared_set_and_types() {
        let ok = search()
            .capture(
                &json!({"filters": {"org_unit": "x", "born": "2020-02-29", "count": 3}}),
                &filters(),
            )
            .expect("matches");
        assert_eq!(ok.filters.expect("filters").len(), 3);
        for body in [
            json!({"filters": {"ghost": "x"}}),
            json!({"filters": {"born": "2021-02-29"}}),
            json!({"filters": {"count": 1.5}}),
            json!({"filters": {"org_unit": 4}}),
        ] {
            assert!(
                matches!(
                    search().capture(&body, &filters()),
                    Err(ReadRefusal::Field(_))
                ),
                "{body}"
            );
        }
        assert!(matches!(
            search().capture(&json!({"filters": []}), &filters()),
            Err(ReadRefusal::Shape(_))
        ));
    }

    #[test]
    fn optional_members_may_be_absent_and_capture_when_present() {
        let captured = search()
            .capture(
                &json!({"filters": {}, "pageSize": 10, "cursor": "c"}),
                &filters(),
            )
            .expect("matches");
        assert_eq!(captured.page_size, Some(10));
        assert_eq!(captured.cursor.as_deref(), Some("c"));
        let bare = search()
            .capture(&json!({"filters": {}}), &filters())
            .expect("matches");
        assert_eq!((bare.page_size, bare.cursor), (None, None));
        assert!(matches!(
            search().capture(&json!({"filters": {}, "pageSize": "10"}), &filters()),
            Err(ReadRefusal::Shape(_))
        ));
    }

    #[test]
    fn a_refusal_never_carries_a_caller_value() {
        let Err(ReadRefusal::Field(reason) | ReadRefusal::Shape(reason)) = search().capture(
            &json!({"filters": {"secret-name-xyz": "secret-value-xyz"}}),
            &filters(),
        ) else {
            panic!("refused");
        };
        assert!(!reason.contains("xyz"), "{reason}");
    }

    #[test]
    fn a_template_that_cannot_be_matched_refuses_at_compile() {
        for text in [
            r#"{"a": "{{record}}"}"#,
            r#"{"a": "{{recordId}}", "b": "{{recordId}}"}"#,
            r#"["{{?recordId}}"]"#,
            "not json",
        ] {
            assert!(ReadRequestTemplate::compile(text).is_err(), "{text}");
        }
    }

    #[test]
    fn query_text_parses_into_the_declared_type() {
        assert_eq!(
            parse_filter_text("7", RecordFieldType::Integer),
            Some(json!(7))
        );
        assert_eq!(parse_filter_text("x", RecordFieldType::Integer), None);
        assert_eq!(
            parse_filter_text("true", RecordFieldType::Boolean),
            Some(json!(true))
        );
        assert_eq!(parse_filter_text("yes", RecordFieldType::Boolean), None);
        assert_eq!(parse_filter_text("2021-02-30", RecordFieldType::Date), None);
        assert_eq!(parse_filter_text("NaN", RecordFieldType::Decimal), None);
    }
}
