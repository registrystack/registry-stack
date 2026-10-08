// SPDX-License-Identifier: Apache-2.0
//! The document tree the reader builds: every node keeps its source span.

use std::fmt;

use serde_json::{Map, Number, Value};

use crate::scalar::{resolve_plain, Resolved};

/// A position in the source text.
///
/// `line` and `column` are 1-based. `column` counts Unicode scalar values from
/// the start of the line, a tab counts as one, and a leading byte-order mark is
/// not counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl Position {
    /// The first character of a file.
    pub const START: Position = Position { line: 1, column: 1 };
}

/// The source range of a node or key, from its first character to the
/// position just after its last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: Position,
    pub end: Position,
}

/// How a string scalar was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScalarStyle {
    /// Unquoted.
    Plain,
    /// `'...'`
    SingleQuoted,
    /// `"..."`
    DoubleQuoted,
    /// `|`
    Literal,
    /// `>`
    Folded,
}

/// A text value and how it reached the tree.
///
/// Its `Debug` output shows `<redacted>` for the text (CFG-SEC-3): a
/// substituted value may be a secret from the environment, and a `Node` or
/// `Document` holding one may reach a log. Keys, styles, and spans still
/// show.
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct Text {
    pub text: String,
    pub style: ScalarStyle,
    /// The value came from a [`crate::ScalarHook`] replacement (environment
    /// substitution in runtime files). A substituted value is always text and
    /// is never resolved again.
    pub substituted: bool,
}

impl fmt::Debug for Text {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Text")
            .field("text", &format_args!("<redacted>"))
            .field("style", &self.style)
            .field("substituted", &self.substituted)
            .finish()
    }
}

/// One node of the document tree.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Node {
    pub value: NodeValue,
    pub span: Span,
}

/// A mapping member: its key, where the key was written, and its value.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Entry {
    pub key: String,
    pub key_span: Span,
    pub value: Node,
}

/// What a node holds, after plain scalars are resolved by the one table
/// (CFG-VAL-1).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum NodeValue {
    Null,
    Bool(bool),
    /// An integer from `i64::MIN` to `u64::MAX`.
    Integer(i128),
    /// A finite binary64 number written with a fraction or an exponent.
    Float(f64),
    String(Text),
    Sequence(Vec<Node>),
    /// Members in source order. Keys are unique.
    Mapping(Vec<Entry>),
}

impl Node {
    /// The member `key` of a mapping node.
    pub fn get(&self, key: &str) -> Option<&Entry> {
        match &self.value {
            NodeValue::Mapping(entries) => entries.iter().find(|entry| entry.key == key),
            _ => None,
        }
    }

    /// The node at an RFC 6901 JSON pointer below this node.
    pub fn pointer(&self, pointer: &str) -> Option<&Node> {
        self.pointer_entry(pointer).map(|(node, _)| node)
    }

    /// The node at `pointer` and, when the last segment is a mapping key, the
    /// span of that key.
    pub(crate) fn pointer_entry(&self, pointer: &str) -> Option<(&Node, Option<Span>)> {
        if pointer.is_empty() {
            return Some((self, None));
        }
        let rest = pointer.strip_prefix('/')?;
        let mut node = self;
        let mut key_span = None;
        for raw in rest.split('/') {
            let segment = unescape_segment(raw);
            match &node.value {
                NodeValue::Mapping(entries) => {
                    let entry = entries.iter().find(|entry| entry.key == segment)?;
                    key_span = Some(entry.key_span);
                    node = &entry.value;
                }
                NodeValue::Sequence(items) => {
                    let index = parse_index(&segment)?;
                    key_span = None;
                    node = items.get(index)?;
                }
                _ => return None,
            }
        }
        Some((node, key_span))
    }

    /// The node as a JSON value. Mapping members keep their keys; integers
    /// and finite numbers convert exactly as written.
    pub fn to_json_value(&self) -> Value {
        match &self.value {
            NodeValue::Null => Value::Null,
            NodeValue::Bool(value) => Value::Bool(*value),
            NodeValue::Integer(value) => {
                if let Ok(signed) = i64::try_from(*value) {
                    Value::Number(Number::from(signed))
                } else {
                    // The tree holds only integers from i64::MIN to u64::MAX.
                    Value::Number(Number::from(u64::try_from(*value).unwrap_or(u64::MAX)))
                }
            }
            NodeValue::Float(value) => Number::from_f64(*value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            NodeValue::String(text) => Value::String(text.text.clone()),
            NodeValue::Sequence(items) => {
                Value::Array(items.iter().map(Node::to_json_value).collect())
            }
            NodeValue::Mapping(entries) => {
                let mut map = Map::new();
                for entry in entries {
                    map.insert(entry.key.clone(), entry.value.to_json_value());
                }
                Value::Object(map)
            }
        }
    }

    /// An unquoted integer or number no value of the tree can represent.
    /// The tree keeps it as its text only until decoding, which refuses it
    /// in the words of the member that reads it; every other read refuses
    /// it before then (CFG-VAL-1).
    pub(crate) fn unrepresentable(&self) -> Option<Unrepresentable> {
        let NodeValue::String(text) = &self.value else {
            return None;
        };
        if text.style != ScalarStyle::Plain || text.substituted {
            return None;
        }
        match resolve_plain(&text.text) {
            Resolved::IntegerOutOfRange => Some(Unrepresentable::Integer {
                negative: text.text.starts_with('-'),
            }),
            Resolved::FloatOutOfRange => Some(Unrepresentable::Number),
            _ => None,
        }
    }

    /// The node's kind in words, for messages. Never the value.
    pub(crate) fn kind_phrase(&self) -> &'static str {
        match &self.value {
            NodeValue::Null => "null",
            NodeValue::Bool(_) => "a boolean",
            NodeValue::Integer(_) => "an integer",
            NodeValue::Float(_) => "a number",
            NodeValue::String(text) if text.substituted => "substituted text",
            NodeValue::String(text) if text.style == ScalarStyle::Plain => "unquoted text",
            NodeValue::String(_) => "quoted text",
            NodeValue::Sequence(_) => "a list",
            NodeValue::Mapping(_) => "a mapping",
        }
    }
}

/// See [`Node::unrepresentable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unrepresentable {
    /// An integer outside `i64::MIN..=u64::MAX`.
    Integer { negative: bool },
    /// A number that overflows binary64.
    Number,
}

/// Escape one JSON pointer segment (RFC 6901).
pub fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

pub(crate) fn unescape_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn parse_index(segment: &str) -> Option<usize> {
    if segment == "0" {
        return Some(0);
    }
    if segment.starts_with('0') || segment.is_empty() {
        return None;
    }
    if !segment.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    segment.parse().ok()
}
