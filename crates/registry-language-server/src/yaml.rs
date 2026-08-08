// SPDX-License-Identifier: Apache-2.0
//! YAML parsing: a small tree-sitter-backed value tree and UTF-16 position mapping.

use anyhow::{Context, Result};
use tower_lsp_server::ls_types::{Position, Range};
use tree_sitter::{Node, Parser};

#[derive(Clone, Debug)]
pub(crate) struct YamlScalar {
    pub(crate) value: String,
    pub(crate) range: Range,
}

#[derive(Clone, Debug)]
pub(crate) struct YamlPair {
    pub(crate) key: YamlScalar,
    pub(crate) value: YamlValue,
}

#[derive(Clone, Debug)]
pub(crate) enum YamlValue {
    Scalar(YamlScalar),
    Mapping(Vec<YamlPair>),
    #[allow(dead_code)]
    Sequence(Vec<YamlValue>),
    Other,
}

impl YamlValue {
    pub(crate) fn as_mapping(&self) -> Option<&[YamlPair]> {
        match self {
            Self::Mapping(entries) => Some(entries),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_sequence(&self) -> Option<&[YamlValue]> {
        match self {
            Self::Sequence(entries) => Some(entries),
            _ => None,
        }
    }

    pub(crate) fn as_scalar(&self) -> Option<&YamlScalar> {
        match self {
            Self::Scalar(scalar) => Some(scalar),
            _ => None,
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<&YamlValue> {
        self.as_mapping()?
            .iter()
            .find(|entry| entry.key.value == key)
            .map(|entry| &entry.value)
    }

    pub(crate) fn get_scalar(&self, key: &str) -> Option<&YamlScalar> {
        self.get(key)?.as_scalar()
    }
}

/// One parsed document: every value the parser could recover, and the range of the first syntax
/// error when the source does not parse cleanly. A document that carries a syntax error still
/// contributes the symbols it does yield, so an edit in one file never blinds the rest of the
/// project.
#[derive(Clone, Debug)]
pub(crate) struct ParsedDocument {
    pub(crate) value: YamlValue,
    pub(crate) syntax_error: Option<Range>,
}

/// The nesting the value tree will follow before it stops descending. Deeper structure degrades to
/// `YamlValue::Other`, which keeps both construction and drop off a stack that would otherwise grow
/// with the input.
pub(crate) const MAX_PARSE_DEPTH: usize = 128;

pub(crate) fn parse_yaml(source: &str) -> Result<ParsedDocument> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .context("failed to load the YAML parser")?;
    let tree = parser
        .parse(source, None)
        .context("the YAML parser did not produce a syntax tree")?;
    let source_map = SourceMap::new(source);
    let root = tree.root_node();
    Ok(ParsedDocument {
        value: value_from_node(root, source, &source_map, 0),
        syntax_error: first_syntax_error(root, &source_map),
    })
}

/// Where a document stops parsing, as one range.
///
/// tree-sitter reports a YAML syntax error by wrapping the whole document in a single ERROR node
/// whose children are the fragments it recovered, so that node's own range spans the entire file.
/// Its last child is the debris the parser could not place, which is the position an author needs.
fn first_syntax_error(root: Node<'_>, source_map: &SourceMap<'_>) -> Option<Range> {
    if !root.has_error() {
        return None;
    }

    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if node.is_error() || node.is_missing() {
            let mut children = node.walk();
            let anchor = node.children(&mut children).last().unwrap_or(node);
            return Some(source_map.range(anchor.start_byte(), anchor.end_byte()));
        }
        if node.has_error() && cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                // A tree that reports an error always holds an ERROR or MISSING node; anchor at the
                // document start rather than stay silent if a grammar ever says otherwise.
                return Some(source_map.range(root.start_byte(), root.start_byte()));
            }
        }
    }
}

fn value_from_node(
    node: Node<'_>,
    source: &str,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> YamlValue {
    if depth >= MAX_PARSE_DEPTH {
        return YamlValue::Other;
    }
    match node.kind() {
        "stream"
        | "document"
        | "block_node"
        | "flow_node"
        | "plain_scalar"
        | "block_sequence_item" => meaningful_named_children(node)
            .last()
            .copied()
            .map(|child| value_from_node(child, source, source_map, depth + 1))
            .unwrap_or(YamlValue::Other),
        // An ERROR node holds the pairs tree-sitter recovered either side of the break, so it reads
        // as the mapping the author was writing.
        "block_mapping" | "flow_mapping" | "ERROR" => {
            let mut entries = Vec::new();
            let mut cursor = node.walk();
            for pair in node
                .named_children(&mut cursor)
                .filter(|child| matches!(child.kind(), "block_mapping_pair" | "flow_pair"))
            {
                let Some(key_node) = pair.child_by_field_name("key") else {
                    continue;
                };
                let Some(key) = scalar_from_node(key_node, source, source_map, depth + 1) else {
                    continue;
                };
                let value = pair
                    .child_by_field_name("value")
                    .map(|value| value_from_node(value, source, source_map, depth + 1))
                    .unwrap_or(YamlValue::Other);
                entries.push(YamlPair { key, value });
            }
            YamlValue::Mapping(entries)
        }
        "block_sequence" | "flow_sequence" => {
            let values = meaningful_named_children(node)
                .into_iter()
                .map(|child| value_from_node(child, source, source_map, depth + 1))
                .collect();
            YamlValue::Sequence(values)
        }
        kind if kind.ends_with("_scalar") => scalar_from_node(node, source, source_map, depth + 1)
            .map(YamlValue::Scalar)
            .unwrap_or(YamlValue::Other),
        _ => YamlValue::Other,
    }
}

fn scalar_from_node(
    node: Node<'_>,
    source: &str,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> Option<YamlScalar> {
    if depth >= MAX_PARSE_DEPTH {
        return None;
    }
    if matches!(
        node.kind(),
        "stream" | "document" | "block_node" | "flow_node" | "plain_scalar" | "block_sequence_item"
    ) {
        return meaningful_named_children(node)
            .last()
            .copied()
            .and_then(|child| scalar_from_node(child, source, source_map, depth + 1));
    }
    if !node.kind().ends_with("_scalar") {
        return None;
    }

    let raw = source.get(node.byte_range())?;
    let (value, start_byte, end_byte) = match node.kind() {
        "double_quote_scalar" => {
            let value = serde_json::from_str::<String>(raw)
                .unwrap_or_else(|_| raw.trim_matches('"').to_owned());
            (
                value,
                node.start_byte() + 1,
                node.end_byte().saturating_sub(1),
            )
        }
        "single_quote_scalar" => (
            raw.trim_matches('\'').replace("''", "'"),
            node.start_byte() + 1,
            node.end_byte().saturating_sub(1),
        ),
        _ => (raw.to_owned(), node.start_byte(), node.end_byte()),
    };
    Some(YamlScalar {
        value,
        range: source_map.range(start_byte, end_byte),
    })
}

fn meaningful_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "comment" | "anchor" | "tag"))
        .collect()
}

pub(crate) struct SourceMap<'a> {
    source: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> SourceMap<'a> {
    pub(crate) fn new(source: &'a str) -> Self {
        let mut line_starts = vec![0];
        for (index, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(index + 1);
            }
        }
        Self {
            source,
            line_starts,
        }
    }

    pub(crate) fn range(&self, start: usize, end: usize) -> Range {
        Range::new(self.position(start), self.position(end))
    }

    pub(crate) fn position(&self, byte: usize) -> Position {
        let byte = byte.min(self.source.len());
        let line = self
            .line_starts
            .partition_point(|line_start| *line_start <= byte)
            .saturating_sub(1);
        let line_start = self.line_starts[line];
        let character = self.source[line_start..byte].encode_utf16().count();
        Position::new(line as u32, character as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_depth(value: &YamlValue) -> usize {
        match value {
            YamlValue::Mapping(entries) => {
                1 + entries
                    .iter()
                    .map(|entry| value_depth(&entry.value))
                    .max()
                    .unwrap_or(0)
            }
            YamlValue::Sequence(entries) => 1 + entries.iter().map(value_depth).max().unwrap_or(0),
            YamlValue::Scalar(_) | YamlValue::Other => 1,
        }
    }

    #[test]
    fn converts_byte_offsets_to_utf16_positions() {
        let parsed = parse_yaml("registry: { id: \"😀demo\" }\n").unwrap();
        let id = parsed
            .value
            .get("registry")
            .and_then(|registry| registry.get_scalar("id"))
            .unwrap();
        assert_eq!(id.range.start, Position::new(0, 17));
        assert_eq!(id.range.end, Position::new(0, 23));
    }

    #[test]
    fn clean_documents_report_no_syntax_error() {
        assert!(parse_yaml("registry: { id: demo }\n")
            .unwrap()
            .syntax_error
            .is_none());
    }

    #[test]
    fn a_syntax_error_is_reported_once_and_leaves_earlier_values_readable() {
        let parsed = parse_yaml("registry:\n  id: demo\nservices:\n  a: [\n").unwrap();

        let error = parsed.syntax_error.expect("the open sequence is reported");
        assert_eq!(error.start, Position::new(3, 5));
        assert_eq!(error.end, Position::new(3, 6));
        assert_eq!(
            parsed
                .value
                .get("registry")
                .and_then(|registry| registry.get_scalar("id"))
                .map(|id| id.value.as_str()),
            Some("demo")
        );
    }

    #[test]
    fn nesting_deeper_than_the_parse_bound_cannot_exhaust_the_stack() {
        let source = format!("value: {}{}\n", "[".repeat(200_000), "]".repeat(200_000));
        assert!(source.len() < 1024 * 1024);

        let parsed = parse_yaml(&source).unwrap();

        assert!(parsed.syntax_error.is_none());
        assert!(value_depth(&parsed.value) <= MAX_PARSE_DEPTH);
    }
}
