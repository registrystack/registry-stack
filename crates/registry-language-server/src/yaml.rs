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

pub(crate) fn is_valid_yaml(source: &str) -> bool {
    parse_yaml(source).is_ok()
}

pub(crate) fn parse_yaml(source: &str) -> Result<YamlValue> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .context("failed to load the YAML parser")?;
    let tree = parser
        .parse(source, None)
        .context("the YAML parser did not produce a syntax tree")?;
    if tree.root_node().has_error() {
        anyhow::bail!("invalid YAML syntax");
    }
    let source_map = SourceMap::new(source);
    Ok(value_from_node(tree.root_node(), source, &source_map))
}

fn value_from_node(node: Node<'_>, source: &str, source_map: &SourceMap<'_>) -> YamlValue {
    match node.kind() {
        "stream"
        | "document"
        | "block_node"
        | "flow_node"
        | "plain_scalar"
        | "block_sequence_item" => meaningful_named_children(node)
            .last()
            .copied()
            .map(|child| value_from_node(child, source, source_map))
            .unwrap_or(YamlValue::Other),
        "block_mapping" | "flow_mapping" => {
            let mut entries = Vec::new();
            let mut cursor = node.walk();
            for pair in node
                .named_children(&mut cursor)
                .filter(|child| matches!(child.kind(), "block_mapping_pair" | "flow_pair"))
            {
                let Some(key_node) = pair.child_by_field_name("key") else {
                    continue;
                };
                let Some(key) = scalar_from_node(key_node, source, source_map) else {
                    continue;
                };
                let value = pair
                    .child_by_field_name("value")
                    .map(|value| value_from_node(value, source, source_map))
                    .unwrap_or(YamlValue::Other);
                entries.push(YamlPair { key, value });
            }
            YamlValue::Mapping(entries)
        }
        "block_sequence" | "flow_sequence" => {
            let values = meaningful_named_children(node)
                .into_iter()
                .map(|child| value_from_node(child, source, source_map))
                .collect();
            YamlValue::Sequence(values)
        }
        kind if kind.ends_with("_scalar") => scalar_from_node(node, source, source_map)
            .map(YamlValue::Scalar)
            .unwrap_or(YamlValue::Other),
        _ => YamlValue::Other,
    }
}

fn scalar_from_node(
    node: Node<'_>,
    source: &str,
    source_map: &SourceMap<'_>,
) -> Option<YamlScalar> {
    if matches!(
        node.kind(),
        "stream" | "document" | "block_node" | "flow_node" | "plain_scalar" | "block_sequence_item"
    ) {
        return meaningful_named_children(node)
            .last()
            .copied()
            .and_then(|child| scalar_from_node(child, source, source_map));
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

    #[test]
    fn converts_byte_offsets_to_utf16_positions() {
        let value = parse_yaml("registry: { id: \"😀demo\" }\n").unwrap();
        let id = value
            .get("registry")
            .and_then(|registry| registry.get_scalar("id"))
            .unwrap();
        assert_eq!(id.range.start, Position::new(0, 17));
        assert_eq!(id.range.end, Position::new(0, 23));
    }
}
