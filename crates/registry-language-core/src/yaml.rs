// SPDX-License-Identifier: Apache-2.0
//! YAML parsing: a small tree-sitter-backed value tree and UTF-16 position mapping.

use anyhow::{Context, Result};
use ls_types::{Position, Range};
use tree_sitter::{Node, Parser};

#[derive(Clone, Debug)]
pub struct YamlScalar {
    pub value: String,
    pub range: Range,
    pub style: ScalarStyle,
}

/// How a scalar is written, which is what decides how text put in its place has to be spelled.
///
/// A quoted scalar's range covers the value and not the quotes around it, so what goes there is
/// escaped for that quote and brings no delimiters of its own. A plain scalar has no quotes to sit
/// inside, so what goes there brings whatever punctuation it needs.
///
/// A block scalar is not here because [`scalar_from_node`] indexes none: its text is not its value,
/// so nothing points at one, nothing is offered at one, and there is no place for a fourth answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
}

/// How `value` is written to occupy the place a scalar of this style occupies, or `None` when it
/// cannot be written there at all.
///
/// A value carrying a line break or another control character is refused rather than escaped. A
/// single-quoted scalar has no escape for either, so there is one style that could not take it, and
/// a name that holds one is a name no author typed and no source published on purpose.
pub fn written_as(value: &str, style: ScalarStyle) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(match style {
        ScalarStyle::Plain if is_plain(value) => value.to_owned(),
        // A plain scalar that would not read back as itself is written as a quoted one instead. The
        // range covers the whole of what the author wrote and none of a quote, so the delimiters go
        // in with it. A JSON string is a YAML double-quoted scalar, so the escaping is the one
        // `serde_json` writes.
        ScalarStyle::Plain => quoted(value),
        ScalarStyle::DoubleQuoted => {
            let quoted = quoted(value);
            quoted[1..quoted.len() - 1].to_owned()
        }
        ScalarStyle::SingleQuoted => value.replace('\'', "''"),
    })
}

/// `value` as a double-quoted scalar, delimiters and all.
fn quoted(value: &str) -> String {
    serde_json::to_string(value).expect("a string writes as a JSON string")
}

/// Whether `value` is read back as this exact string wherever a plain scalar may sit.
///
/// The rule is narrower than YAML's, deliberately. A flow collection gives `[`, `]`, `{`, `}`, and
/// `,` a meaning a block context does not, and the same field of the same form is written both
/// ways, so a value holding any of them is refused here rather than judged against a context this
/// cannot see. What is left is refused too if the reader resolves it to something other than the
/// string it is spelled with, which is what `null`, `true`, and `42` are. A value refused here is
/// quoted, which is never wrong and at worst is more punctuation than the author would have typed.
///
/// An indicator character only opens a node, so the first character is judged by a shorter list than
/// the rest. That is what lets a fact path keep its `*` and stay the plain scalar its author wrote.
fn is_plain(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == '_' || first == '/') {
        return false;
    }
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_./*".contains(character)))
    {
        return false;
    }
    serde_norway::from_str::<String>(value).is_ok_and(|read| read == value)
}

#[derive(Clone, Debug)]
pub struct YamlPair {
    pub key: YamlScalar,
    pub value: YamlValue,
}

#[derive(Clone, Debug)]
pub enum YamlValue {
    Scalar(YamlScalar),
    Mapping(Vec<YamlPair>),
    Sequence(Vec<YamlValue>),
    Other,
}

impl YamlValue {
    pub fn as_mapping(&self) -> Option<&[YamlPair]> {
        match self {
            Self::Mapping(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_sequence(&self) -> Option<&[YamlValue]> {
        match self {
            Self::Sequence(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_scalar(&self) -> Option<&YamlScalar> {
        match self {
            Self::Scalar(scalar) => Some(scalar),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&YamlValue> {
        self.as_mapping()?
            .iter()
            .find(|entry| entry.key.value == key)
            .map(|entry| &entry.value)
    }

    pub fn get_scalar(&self, key: &str) -> Option<&YamlScalar> {
        self.get(key)?.as_scalar()
    }
}

/// One parsed document: every value the parser could recover, and the range of the first syntax
/// error when the source does not parse cleanly. A document that carries a syntax error still
/// contributes the symbols it does yield, so an edit in one file never blinds the rest of the
/// project.
#[derive(Clone, Debug)]
pub struct ParsedDocument {
    pub value: YamlValue,
    pub syntax_error: Option<Range>,
}

/// The nesting the value tree will follow before it stops descending. Deeper structure degrades to
/// `YamlValue::Other`, which keeps both construction and drop off a stack that would otherwise grow
/// with the input.
pub const MAX_PARSE_DEPTH: usize = 128;

pub fn parse_yaml(source: &str) -> Result<ParsedDocument> {
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
    // Two forms whose source text is not their value, and neither is decoded here.
    //
    // A block scalar's text opens with the indicator that decides how it ends and how much of each
    // line's indentation belongs to the value, so `|-`, the newline, and the indentation are all in
    // `raw` and in none of what the document means. A scalar of any other form written over more
    // than one line is folded, plainly and inside quotes alike, so its line breaks and the
    // indentation that continues it are not in the value either.
    //
    // What is stored has to be what `serde_norway` reads, because that is the deserializer the
    // authoring form reads the same document with. A name stored as its source text resolves to
    // nothing on screen while the compiler resolves it, which reports a project the compiler
    // accepts. Storing nothing costs the navigation on that one field and reports nothing at all,
    // so it is what a form no cheap rule decodes faithfully is worth.
    if node.kind() == "block_scalar" || raw.contains('\n') {
        return None;
    }

    // A quoted scalar's escapes are decoded by handing its own source text to `serde_norway`, rather
    // than by a hand-written unescaper, because `raw` is already a complete, valid YAML document on
    // its own: a quoted scalar's meaning does not depend on the block or flow context around it. A
    // double-quoted scalar accepts escapes `serde_json` does not (`\x41`, `\_`, `\e`, and more), and a
    // hand-written single-quote rule that trims every leading and trailing quote mishandles a value
    // whose content itself starts or ends with an escaped quote, such as `'''a'''`. Both are the same
    // mistake `written_as` warns against for the double-quoted case above: a decoder that is not the
    // one the compiler reads with. An escape `serde_norway` refuses is refused here too, by the same
    // precedent that leaves a folded scalar out of the index rather than store its raw spelling.
    let (value, style, start_byte, end_byte) = match node.kind() {
        "double_quote_scalar" | "single_quote_scalar" => {
            let value = serde_norway::from_str::<String>(raw).ok()?;
            let style = if node.kind() == "double_quote_scalar" {
                ScalarStyle::DoubleQuoted
            } else {
                ScalarStyle::SingleQuoted
            };
            (
                value,
                style,
                node.start_byte() + 1,
                node.end_byte().saturating_sub(1),
            )
        }
        _ => (
            raw.to_owned(),
            ScalarStyle::Plain,
            node.start_byte(),
            node.end_byte(),
        ),
    };
    Some(YamlScalar {
        value,
        style,
        range: source_map.range(start_byte, end_byte),
    })
}

fn meaningful_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "comment" | "anchor" | "tag"))
        .collect()
}

pub struct SourceMap<'a> {
    source: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> SourceMap<'a> {
    pub fn new(source: &'a str) -> Self {
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

    pub fn range(&self, start: usize, end: usize) -> Range {
        Range::new(self.position(start), self.position(end))
    }

    pub fn position(&self, byte: usize) -> Position {
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
    use std::collections::BTreeMap;

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

    /// Every form a scalar can be written in, against the reading the compiler will do of it.
    ///
    /// `serde_norway` is the deserializer `registry_evidence_authoring` reads a document with, so a
    /// value stored here that differs from the one it reads is a name resolved against a document
    /// the compiler reads differently: the editor would report a project it accepts, which is the
    /// one thing an editor beside a compiler may not do. A form left out of the index is allowed,
    /// and is what this asks for wherever a cheap rule cannot decode the form faithfully.
    #[test]
    fn a_scalar_is_read_as_the_compiler_reads_it_or_left_out_of_the_index() {
        for source in [
            "concept: is_adult\n",
            "concept: \"is_adult\"\n",
            "concept: 'is_adult'\n",
            "concept: \"is: adult\"\n",
            "concept: 'it''s'\n",
            "concept: \"\\u00e9t\\u00e9\"\n",
            "concept: |-\n  is_adult\n",
            "concept: |\n  is_adult\n",
            "concept: >-\n  is_adult\n",
            "concept: >\n  is_adult\n",
            "concept: |-\n  is_adult\n  and_more\n",
            "concept: is\n  adult\n",
            "concept: \"is\n  adult\"\n",
            "concept: 'is\n  adult'\n",
        ] {
            let parsed = parse_yaml(source).expect("the fragment parses");
            let Some(indexed) = parsed.value.get_scalar("concept") else {
                continue;
            };
            let read = serde_norway::from_str::<BTreeMap<String, String>>(source)
                .expect("the fragment is a mapping of strings");
            assert_eq!(indexed.value, read["concept"], "{source:?}");
        }
    }

    /// The forms the authoring form's own names are written in are all read, so the rule above
    /// cannot be satisfied by indexing nothing.
    #[test]
    fn the_forms_a_name_is_written_in_are_all_read() {
        for (source, value) in [
            ("concept: is_adult\n", "is_adult"),
            ("concept: \"is_adult\"\n", "is_adult"),
            ("concept: 'is_adult'\n", "is_adult"),
        ] {
            assert_eq!(
                parse_yaml(source)
                    .unwrap()
                    .value
                    .get_scalar("concept")
                    .map(|scalar| scalar.value.as_str()),
                Some(value),
                "{source:?}"
            );
        }
    }

    /// The forms that are left out, named so that a change of mind about one of them is a change to
    /// this list. Each one is folded by a rule of its own, and the source text is not the value in
    /// any of them.
    #[test]
    fn a_scalar_written_over_more_than_one_line_is_left_out_of_the_index() {
        for source in [
            "concept: |-\n  is_adult\n",
            "concept: |\n  is_adult\n",
            "concept: >-\n  is_adult\n",
            "concept: is\n  adult\n",
            "concept: \"is\n  adult\"\n",
            "concept: 'is\n  adult'\n",
        ] {
            assert!(
                parse_yaml(source)
                    .unwrap()
                    .value
                    .get_scalar("concept")
                    .is_none(),
                "{source:?}"
            );
        }
    }

    /// A name written for the style of the scalar it lands in reads back as that name.
    ///
    /// The check is the reading rather than the spelling. The document is built the way an accepted
    /// offer builds one, by putting the text where the value stood, and it is read back with the
    /// reader the form itself uses, so a rule that escaped a character wrongly fails here whatever
    /// the escaping looks like.
    #[test]
    fn a_name_written_for_a_style_reads_back_as_that_name() {
        for name in [
            "readPerson",
            "/records/*/date_of_birth",
            "read: person",
            "say \"hi\"",
            "it's",
            "both ' and \"",
            "null",
            "42",
            "a, b",
            "]",
            "#comment",
            " leading",
            "trailing ",
            "",
        ] {
            for (style, document) in [
                (ScalarStyle::Plain, "concept: {}\n"),
                (ScalarStyle::DoubleQuoted, "concept: \"{}\"\n"),
                (ScalarStyle::SingleQuoted, "concept: '{}'\n"),
            ] {
                let written =
                    written_as(name, style).expect("a name free of control characters is written");
                let source = document.replace("{}", &written);
                let read = serde_norway::from_str::<BTreeMap<String, String>>(&source)
                    .unwrap_or_else(|error| panic!("{source:?} does not parse: {error}"));
                assert_eq!(
                    read.get("concept").map(String::as_str),
                    Some(name),
                    "{source:?}"
                );
            }
        }
    }

    /// A name carrying a control character is written for no style at all. A single-quoted scalar
    /// has no escape for one, so refusing it everywhere keeps the three styles answerable by the
    /// same rule.
    #[test]
    fn a_name_carrying_a_control_character_is_written_for_no_style() {
        for style in [
            ScalarStyle::Plain,
            ScalarStyle::DoubleQuoted,
            ScalarStyle::SingleQuoted,
        ] {
            assert_eq!(written_as("two\nlines", style), None, "{style:?}");
        }
    }

    /// A double-quoted scalar accepts escapes JSON does not, such as `\x` and `\_`. Decoding it any
    /// other way than `serde_norway` itself stores a name the compiler reads differently, which is
    /// exactly the report the governing rule above forbids.
    #[test]
    fn a_double_quoted_scalar_decodes_escapes_serde_json_does_not_accept() {
        let source = "concept: \"is\\x5fadult\"\n";
        let read = serde_norway::from_str::<BTreeMap<String, String>>(source)
            .expect("the fragment is a mapping of strings");
        assert_eq!(read["concept"], "is_adult");

        let indexed = parse_yaml(source)
            .unwrap()
            .value
            .get_scalar("concept")
            .cloned()
            .expect("the scalar decodes");
        assert_eq!(indexed.value, read["concept"]);
    }

    /// An escape `serde_norway` itself refuses is left out of the index rather than stored as its raw
    /// spelling, the same precedent a block scalar sets above.
    #[test]
    fn a_double_quoted_scalar_with_an_invalid_escape_is_left_out_of_the_index() {
        let source = "concept: \"bad\\q\"\n";
        assert!(parse_yaml(source)
            .unwrap()
            .value
            .get_scalar("concept")
            .is_none());
    }

    #[test]
    fn an_ordinary_double_quoted_scalar_is_unchanged() {
        let source = "concept: \"is_adult\"\n";
        assert_eq!(
            parse_yaml(source)
                .unwrap()
                .value
                .get_scalar("concept")
                .map(|scalar| scalar.value.as_str()),
            Some("is_adult")
        );
    }

    /// `trim_matches` strips every leading and trailing quote rather than only the one pair YAML
    /// treats as delimiters, so a doubled quote at either edge of the content used to disappear along
    /// with the real delimiters. `'''a'''` is YAML for `'a'`: the outer quotes delimit the scalar and
    /// the inner `''` is an escaped quote, not a second delimiter.
    #[test]
    fn single_quoted_scalars_decode_doubled_quotes_at_any_position() {
        for (source, value) in [
            ("concept: 'it''s'\n", "it's"),
            ("concept: '''a'''\n", "'a'"),
        ] {
            assert_eq!(
                parse_yaml(source)
                    .unwrap()
                    .value
                    .get_scalar("concept")
                    .map(|scalar| scalar.value.as_str()),
                Some(value),
                "{source:?}"
            );
        }
    }

    /// Decoding the scalar through `serde_norway` changes what `value` holds but must not change what
    /// `range` covers: completion still has to replace exactly the text between the quotes, not the
    /// (possibly shorter) decoded value.
    #[test]
    fn a_decoded_scalars_range_still_covers_only_the_quoted_content() {
        let source = "concept: \"is\\x5fadult\"\n";
        let parsed = parse_yaml(source).unwrap();
        let scalar = parsed.value.get_scalar("concept").unwrap();
        assert_eq!(scalar.value, "is_adult");

        let opening_quote = source.find('"').unwrap();
        let closing_quote = source.rfind('"').unwrap();
        assert_eq!(
            scalar.range.start,
            Position::new(0, (opening_quote + 1) as u32)
        );
        assert_eq!(scalar.range.end, Position::new(0, closing_quote as u32));
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
