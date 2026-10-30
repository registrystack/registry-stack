// SPDX-License-Identifier: Apache-2.0

//! A compiled envelope template. The template text is read once, at load,
//! into a tree: a literal is a JSON value no later step rescans, and a slot
//! is a named hole the renderer fills from the request's values. A
//! deployment's parameterized-part value is bound into the tree as a
//! literal, so no value, however it spells quotes, backslashes, or `{{`,
//! can become a slot or alter the template's structure.

use std::collections::BTreeMap;

use registry_adapter_core::{decode_slot, parse_envelope_template, ENVELOPE_SLOTS};
use registry_platform_yaml::ExternalId;
use serde_json::{Map, Value};

#[derive(Clone, Debug)]
enum Node {
    Literal(Value),
    Slot { name: String, optional: bool },
    Object(Vec<(String, Node)>),
    Array(Vec<Node>),
}

/// An envelope template compiled for rendering.
#[derive(Clone, Debug)]
pub struct CompiledEnvelope(Node);

impl CompiledEnvelope {
    /// Compile `text`, binding each parameterized part: a string member
    /// whose key and string value both equal the part name takes the
    /// deployment's value for that part.
    ///
    /// The template is then rendered once with a stand-in for every slot
    /// of the closed vocabulary, so a template the renderer cannot fill
    /// refuses here and not on the first request.
    ///
    /// # Errors
    ///
    /// A value-free account of why the template cannot be rendered.
    pub fn compile(text: &str, parts: &BTreeMap<ExternalId, String>) -> Result<Self, String> {
        let parsed = parse_envelope_template(text)?;
        let compiled = Self(node(&parsed, parts)?);
        let stand_ins: BTreeMap<&str, Value> = ENVELOPE_SLOTS
            .iter()
            .map(|name| (*name, Value::Null))
            .collect();
        compiled.render(&stand_ins)?;
        Ok(compiled)
    }

    /// Fill the template. A required slot with no value is a fault; an
    /// optional slot with none drops the member that carried it.
    ///
    /// # Errors
    ///
    /// The name of the required slot that has no value.
    pub fn render(&self, slots: &BTreeMap<&str, Value>) -> Result<Value, String> {
        fill(&self.0, slots)?.ok_or_else(|| "the envelope root is an absent slot".to_owned())
    }
}

fn node(template: &Value, parts: &BTreeMap<ExternalId, String>) -> Result<Node, String> {
    match template {
        Value::String(text) => Ok(match decode_slot(text) {
            Some((name, optional)) => Node::Slot {
                name: name.to_owned(),
                optional,
            },
            None => Node::Literal(template.clone()),
        }),
        Value::Object(members) => {
            let mut compiled = Vec::with_capacity(members.len());
            for (key, member) in members {
                let bound = match (member, parts.iter().find(|(name, _)| name.as_str() == key)) {
                    (Value::String(text), Some((name, value))) if text == name.as_str() => {
                        Node::Literal(Value::String(value.clone()))
                    }
                    _ => node(member, parts)?,
                };
                compiled.push((key.clone(), bound));
            }
            Ok(Node::Object(compiled))
        }
        Value::Array(items) => {
            let compiled = items
                .iter()
                .map(|item| node(item, parts))
                .collect::<Result<Vec<_>, _>>()?;
            if compiled.iter().any(is_optional_slot) {
                return Err(
                    "an optional slot fills an object member, never an array item".to_owned(),
                );
            }
            Ok(Node::Array(compiled))
        }
        other => Ok(Node::Literal(other.clone())),
    }
}

fn is_optional_slot(node: &Node) -> bool {
    matches!(node, Node::Slot { optional: true, .. })
}

fn fill(node: &Node, slots: &BTreeMap<&str, Value>) -> Result<Option<Value>, String> {
    match node {
        Node::Literal(value) => Ok(Some(value.clone())),
        Node::Slot { name, optional } => match slots.get(name.as_str()) {
            Some(value) => Ok(Some(value.clone())),
            None if *optional => Ok(None),
            None => Err(format!("the slot {name} has no value")),
        },
        Node::Object(members) => {
            let mut object = Map::new();
            for (key, member) in members {
                if let Some(value) = fill(member, slots)? {
                    object.insert(key.clone(), value);
                }
            }
            Ok(Some(Value::Object(object)))
        }
        Node::Array(items) => {
            let mut array = Vec::with_capacity(items.len());
            for item in items {
                array.push(
                    fill(item, slots)?
                        .ok_or_else(|| "an optional slot fills an array item".to_owned())?,
                );
            }
            Ok(Some(Value::Array(array)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn slots(pairs: &[(&'static str, Value)]) -> BTreeMap<&'static str, Value> {
        pairs.iter().cloned().collect()
    }

    fn part(name: &str, value: &str) -> BTreeMap<ExternalId, String> {
        BTreeMap::from([(ExternalId::new(name).unwrap(), value.to_owned())])
    }

    #[test]
    fn a_slot_takes_the_value_whole_whether_quoted_or_bare() {
        let compiled = CompiledEnvelope::compile(
            r#"{"data": {{record}}, "meta": {"type": "{{recordType}}"}}"#,
            &BTreeMap::new(),
        )
        .unwrap();
        let rendered = compiled
            .render(&slots(&[
                ("record", json!({"a": 1})),
                ("recordType", json!("person")),
            ]))
            .unwrap();
        assert_eq!(
            rendered,
            json!({"data": {"a": 1}, "meta": {"type": "person"}})
        );
    }

    #[test]
    fn a_slot_value_holding_a_placeholder_or_quotes_is_never_rescanned() {
        let compiled =
            CompiledEnvelope::compile(r#"{"data": {{record}}}"#, &BTreeMap::new()).unwrap();
        let record = json!({"name": "{{record}} \"q\" \\ {{?x}}"});
        let rendered = compiled
            .render(&slots(&[("record", record.clone())]))
            .unwrap();
        assert_eq!(rendered, json!({"data": record}));
    }

    #[test]
    fn an_absent_optional_slot_drops_its_member() {
        let compiled = CompiledEnvelope::compile(
            r#"{"status": {{status}}, "detail": "{{?problemDetail}}"}"#,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            compiled.render(&slots(&[("status", json!(404))])).unwrap(),
            json!({"status": 404})
        );
        assert_eq!(
            compiled
                .render(&slots(&[
                    ("status", json!(404)),
                    ("problemDetail", json!("gone \"x\""))
                ]))
                .unwrap(),
            json!({"status": 404, "detail": "gone \"x\""})
        );
    }

    #[test]
    fn a_part_value_with_a_quote_a_backslash_and_a_placeholder_binds_as_text() {
        let value = r#"ci"vil\ {{record}} "#;
        let compiled = CompiledEnvelope::compile(
            r#"{"data": {{record}}, "meta": {"registryIdentifier": "registryIdentifier", "other": "registryIdentifier", "after": "{{recordType}}"}}"#,
            &part("registryIdentifier", value),
        )
        .unwrap();
        let rendered = compiled
            .render(&slots(&[
                ("record", json!({"registryIdentifier": "from-the-record"})),
                ("recordType", json!("person")),
            ]))
            .unwrap();
        assert_eq!(
            rendered,
            json!({
                "data": {"registryIdentifier": "from-the-record"},
                "meta": {
                    "registryIdentifier": value,
                    "other": "registryIdentifier",
                    "after": "person"
                }
            })
        );
    }

    #[test]
    fn a_part_binds_only_the_member_of_its_own_name_with_its_own_stand_in() {
        let compiled = CompiledEnvelope::compile(
            r#"{"registryIdentifier": "something else", "x": {"registryIdentifier": "registryIdentifier"}}"#,
            &part("registryIdentifier", "bound"),
        )
        .unwrap();
        assert_eq!(
            compiled.render(&BTreeMap::new()).unwrap(),
            json!({"registryIdentifier": "something else", "x": {"registryIdentifier": "bound"}})
        );
    }

    #[test]
    fn a_template_the_renderer_cannot_fill_refuses_at_compile() {
        let unknown = CompiledEnvelope::compile(r#"{"a": {{notASlot}}}"#, &BTreeMap::new());
        assert!(unknown.unwrap_err().contains("notASlot"));
        let in_array = CompiledEnvelope::compile(r#"{"a": ["{{?nextCursor}}"]}"#, &BTreeMap::new());
        assert!(in_array.is_err());
        assert!(CompiledEnvelope::compile(r#"{"a": "#, &BTreeMap::new()).is_err());
    }

    #[test]
    fn a_missing_required_slot_is_a_fault() {
        let compiled = CompiledEnvelope::compile(r#"{"a": {{record}}}"#, &BTreeMap::new()).unwrap();
        assert!(compiled.render(&slots(&[])).is_err());
    }
}
