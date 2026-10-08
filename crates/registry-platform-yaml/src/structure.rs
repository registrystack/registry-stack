// SPDX-License-Identifier: Apache-2.0
//! Parser events to the document tree, refusing what the subset excludes.
//!
//! Everything found here is a structural problem (CFG-DIAG-5): all of them
//! are reported together, and a document with one is not decoded.

use std::collections::HashMap;

use saphyr_parser::{Event, Marker, Parser, ScalarStyle as EventStyle, ScanError};

use crate::messages::{self, Problem};
use crate::node::{
    escape_pointer_segment, Entry, Node, NodeValue, Position, ScalarStyle, Span, Text,
};
use crate::scalar::{resolve_plain, Resolved};

/// The deepest nesting of lists and mappings a document may use.
pub const MAXIMUM_DEPTH: usize = 128;

/// A scalar the reader hands to a [`ScalarHook`]: a mapping key, or a text
/// value.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScalarSite<'a> {
    /// RFC 6901 pointer to the value, or for a key, to the member it names.
    pub pointer: &'a str,
    /// The mapping keys on the way from the root, ending with the member's
    /// own key when it has one. List indices are not included.
    pub keys: &'a [&'a str],
    pub text: &'a str,
    pub style: ScalarStyle,
    pub span: Span,
}

/// A hook's refusal, reported at the scalar's position as a structural
/// problem. The message and action follow the same rule as the reader's own:
/// they never repeat a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub message: String,
    pub suggested_action: String,
}

/// Inspects or replaces scalars while the tree is built, before the envelope
/// check. Runtime configuration uses it for `${NAME}` substitution; an
/// authored-file check uses it to refuse substitution expressions.
pub trait ScalarHook {
    /// Called for every mapping key.
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        let _ = site;
        Ok(())
    }

    /// Called for every value that resolves to text. Returning a replacement
    /// stores it as substituted text, which is never resolved again.
    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        let _ = site;
        Ok(None)
    }
}

pub(crate) struct Built {
    /// `None` when the stream holds no document, or when a fatal problem
    /// stopped the build.
    pub root: Option<Node>,
    pub problems: Vec<Problem>,
    /// Unquoted numbers no tree value can represent, kept in the tree as
    /// their text (see `Node::unrepresentable`). A read that does not decode
    /// reports these with `problems`.
    pub unrepresentable: Vec<Problem>,
}

impl Built {
    /// A read refused before the tree was built.
    pub(crate) fn refused(problem: Problem) -> Built {
        Built {
            root: None,
            problems: vec![problem],
            unrepresentable: Vec::new(),
        }
    }
}

pub(crate) fn build(text: &str, hook: Option<&mut dyn ScalarHook>) -> Built {
    let mut builder = Builder {
        text,
        stack: Vec::new(),
        problems: Vec::new(),
        unrepresentable: Vec::new(),
        hook,
        root: None,
        documents: 0,
        last_end: Marker::new(0, 1, 0),
        cursor: (0, 0),
    };
    let fatal = builder.run();
    Built {
        root: if fatal { None } else { builder.root },
        problems: builder.problems,
        unrepresentable: builder.unrepresentable,
    }
}

enum Frame {
    Sequence {
        start: Position,
        start_index: usize,
        items: Vec<Node>,
    },
    Mapping {
        start: Position,
        start_index: usize,
        entries: Vec<Entry>,
        state: MapState,
        seen: HashMap<String, Position>,
    },
}

enum MapState {
    ExpectKey,
    ExpectValue {
        /// The key, or `None` when the key was refused and the value is read
        /// only to be dropped.
        key: Option<(String, Span)>,
        /// The pointer segment problems inside the value report.
        segment: Option<String>,
    },
}

struct Builder<'t, 'h> {
    text: &'t str,
    stack: Vec<Frame>,
    problems: Vec<Problem>,
    unrepresentable: Vec<Problem>,
    hook: Option<&'h mut dyn ScalarHook>,
    root: Option<Node>,
    documents: usize,
    /// Where the previous event ended. A node's anchor and tag lie between
    /// it and the node's content, which is where the parser places the
    /// node.
    last_end: Marker,
    /// The character index and byte offset of the last offset lookup, so
    /// lookups that move forward through the text stay linear.
    cursor: (usize, usize),
}

fn position(marker: &Marker) -> Position {
    Position {
        line: marker.line(),
        column: marker.col() + 1,
    }
}

fn span(event_span: &saphyr_parser::Span) -> Span {
    Span {
        start: position(&event_span.start),
        end: position(&event_span.end),
    }
}

impl Builder<'_, '_> {
    /// Returns whether a fatal problem stopped the build.
    fn run(&mut self) -> bool {
        for item in Parser::new_from_str(self.text) {
            let (event, event_span) = match item {
                Ok(item) => item,
                Err(error) => {
                    let problem = self.classify_syntax_error(&error);
                    self.problems.push(problem);
                    return true;
                }
            };
            let span = span(&event_span);
            let content = event_span.start;
            let previous_end = std::mem::replace(&mut self.last_end, event_span.end);
            match event {
                Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
                Event::DocumentStart(_) => {
                    self.documents += 1;
                    if self.documents > 1 {
                        self.problems.push(Problem::error(
                            "yaml.multiple-documents",
                            "",
                            Some(span.start),
                            messages::multiple_documents(),
                        ));
                        return false;
                    }
                }
                Event::Alias(_) => {
                    self.problem_here("yaml.alias", span.start, messages::alias());
                    self.insert_refused(span);
                }
                Event::Scalar(value, style, anchor, tag) => {
                    self.refuse_properties(anchor != 0, tag.is_some(), &previous_end, &content);
                    let style = convert_style(style);
                    if self.expects_key() {
                        self.scalar_key(&value, style, span);
                    } else {
                        let span = if style == ScalarStyle::Plain && value.is_empty() {
                            self.empty_value_span(span, &previous_end, &content)
                        } else {
                            span
                        };
                        let node = self.scalar_value(value.into_owned(), style, span);
                        self.insert_value(node);
                    }
                }
                Event::SequenceStart(anchor, ref tag) | Event::MappingStart(anchor, ref tag) => {
                    self.refuse_properties(anchor != 0, tag.is_some(), &previous_end, &content);
                    if self.stack.len() + 1 > MAXIMUM_DEPTH {
                        self.problems.push(Problem::error(
                            "yaml.too-deep",
                            self.pointer(),
                            Some(span.start),
                            messages::too_deep(MAXIMUM_DEPTH),
                        ));
                        return true;
                    }
                    let start_index = event_span.start.index();
                    let frame = if matches!(event, Event::SequenceStart(..)) {
                        Frame::Sequence {
                            start: span.start,
                            start_index,
                            items: Vec::new(),
                        }
                    } else {
                        Frame::Mapping {
                            start: span.start,
                            start_index,
                            entries: Vec::new(),
                            state: MapState::ExpectKey,
                            seen: HashMap::new(),
                        }
                    };
                    self.stack.push(frame);
                }
                Event::SequenceEnd | Event::MappingEnd => {
                    let Some(frame) = self.stack.pop() else {
                        continue;
                    };
                    let node = match frame {
                        Frame::Sequence { start, items, .. } => Node {
                            value: NodeValue::Sequence(items),
                            span: Span {
                                start,
                                end: span.end,
                            },
                        },
                        Frame::Mapping { start, entries, .. } => Node {
                            value: NodeValue::Mapping(entries),
                            span: Span {
                                start,
                                end: span.end,
                            },
                        },
                    };
                    if self.expects_key() {
                        // A list or mapping used as a key.
                        self.problem_here(
                            "yaml.non-string-key",
                            node.span.start,
                            messages::complex_key(),
                        );
                        self.set_refused_key(None);
                    } else {
                        self.insert_value(node);
                    }
                }
            }
        }
        false
    }

    /// Report a node's anchor and tag at the `&` and the `!` that start
    /// them; the parser places the node at its content instead.
    fn refuse_properties(&mut self, anchor: bool, tag: bool, from: &Marker, content: &Marker) {
        if !anchor && !tag {
            return;
        }
        let (anchor_at, tag_at) = self.property_positions(from, content);
        if anchor {
            let at = anchor_at.unwrap_or(position(content));
            self.problem_here("yaml.anchor", at, messages::anchor());
        }
        if tag {
            let at = tag_at.unwrap_or(position(content));
            self.problem_here("yaml.tag", at, messages::tag());
        }
    }

    /// An empty value has no first character. It is placed at its key, or
    /// at the `-` that opens its list item; the parser places it after the
    /// indicator, at the end of the line or at the next token.
    fn empty_value_span(&mut self, span: Span, from: &Marker, content: &Marker) -> Span {
        let at = match self.stack.last() {
            Some(Frame::Mapping {
                state:
                    MapState::ExpectValue {
                        key: Some((_, key_span)),
                        ..
                    },
                ..
            }) => Some(key_span.start),
            Some(Frame::Sequence { .. }) => self
                .tokens_between(from, content)
                .into_iter()
                .rev()
                .find_map(|(c, at)| (c == '-').then_some(at)),
            _ => None,
        };
        at.map_or(span, |start| Span { start, end: start })
    }

    /// The first `&` and `!` that start a token between two parser
    /// positions.
    fn property_positions(
        &mut self,
        from: &Marker,
        content: &Marker,
    ) -> (Option<Position>, Option<Position>) {
        let tokens = self.tokens_between(from, content);
        let first = |wanted: char| {
            tokens
                .iter()
                .find_map(|&(c, at)| (c == wanted).then_some(at))
        };
        (first('&'), first('!'))
    }

    /// The characters between two parser positions that are neither
    /// whitespace, nor inside a comment, nor inside a node property after
    /// its first character. Only indicators, whitespace, comments, and node
    /// properties lie between two events, so outside comments a `&` or `!`
    /// starts a property and a `-` is a list item indicator.
    fn tokens_between(&mut self, from: &Marker, content: &Marker) -> Vec<(char, Position)> {
        if content.index() <= from.index() {
            return Vec::new();
        }
        let start = self.byte_offset(from.index());
        let end = self.byte_offset(content.index());
        let mut at = position(from);
        let mut tokens = Vec::new();
        let (mut in_comment, mut in_property) = (false, false);
        let mut chars = self.text[start..end].chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\r' | '\n' => {
                    if c == '\r' && chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    at.line += 1;
                    at.column = 1;
                    in_comment = false;
                    in_property = false;
                    continue;
                }
                _ if in_comment => {}
                ' ' | '\t' => in_property = false,
                _ if in_property => {}
                '#' => in_comment = true,
                _ => {
                    tokens.push((c, at));
                    in_property = c == '&' || c == '!';
                }
            }
            at.column += 1;
        }
        tokens
    }

    /// The byte offset of a parser character index.
    fn byte_offset(&mut self, char_index: usize) -> usize {
        let (mut chars, mut bytes) = if char_index >= self.cursor.0 {
            self.cursor
        } else {
            (0, 0)
        };
        for c in self.text[bytes..].chars() {
            if chars == char_index {
                break;
            }
            chars += 1;
            bytes += c.len_utf8();
        }
        self.cursor = (chars, bytes);
        bytes
    }

    fn problem_here(&mut self, code: &str, at: Position, text: messages::Text) {
        let pointer = self.pointer();
        self.problems
            .push(Problem::error(code, pointer, Some(at), text));
    }

    fn expects_key(&self) -> bool {
        matches!(
            self.stack.last(),
            Some(Frame::Mapping {
                state: MapState::ExpectKey,
                ..
            })
        )
    }

    /// The pointer of the node being built now.
    fn pointer(&self) -> String {
        let mut pointer = String::new();
        for frame in &self.stack {
            match frame {
                Frame::Sequence { items, .. } => {
                    pointer.push('/');
                    pointer.push_str(&items.len().to_string());
                }
                Frame::Mapping {
                    state:
                        MapState::ExpectValue {
                            segment: Some(segment),
                            ..
                        },
                    ..
                } => {
                    pointer.push('/');
                    pointer.push_str(&escape_pointer_segment(segment));
                }
                Frame::Mapping { .. } => {}
            }
        }
        pointer
    }

    /// The mapping keys on the way to the node being built now.
    fn keys(&self) -> Vec<&str> {
        self.stack
            .iter()
            .filter_map(|frame| match frame {
                Frame::Mapping {
                    state:
                        MapState::ExpectValue {
                            segment: Some(segment),
                            ..
                        },
                    ..
                } => Some(segment.as_str()),
                _ => None,
            })
            .collect()
    }

    fn set_refused_key(&mut self, segment: Option<String>) {
        if let Some(Frame::Mapping { state, .. }) = self.stack.last_mut() {
            *state = MapState::ExpectValue { key: None, segment };
        }
    }

    fn scalar_key(&mut self, value: &str, style: ScalarStyle, span: Span) {
        let pointer = format!("{}/{}", self.pointer(), escape_pointer_segment(value));
        if style == ScalarStyle::Plain {
            if value == "<<" {
                self.problems.push(Problem::error(
                    "yaml.merge-key",
                    pointer,
                    Some(span.start),
                    messages::merge_key(),
                ));
                self.set_refused_key(Some(value.to_string()));
                return;
            }
            let kind = match resolve_plain(value) {
                Resolved::String => None,
                Resolved::Ambiguous => {
                    self.problems.push(Problem::error(
                        "yaml.ambiguous-number",
                        pointer,
                        Some(span.start),
                        messages::ambiguous_number(),
                    ));
                    self.set_refused_key(Some(value.to_string()));
                    return;
                }
                Resolved::Null => Some("null"),
                Resolved::Bool(_) => Some("a boolean"),
                Resolved::Integer(_) | Resolved::IntegerOutOfRange => Some("an integer"),
                Resolved::Float(_) | Resolved::FloatOutOfRange => Some("a number"),
            };
            if let Some(kind) = kind {
                self.problems.push(Problem::error(
                    "yaml.non-string-key",
                    pointer,
                    Some(span.start),
                    messages::non_string_key(kind),
                ));
                self.set_refused_key(Some(value.to_string()));
                return;
            }
        }
        let first = match self.stack.last() {
            Some(Frame::Mapping { seen, .. }) => seen.get(value).copied(),
            _ => None,
        };
        if let Some(first) = first {
            self.problems.push(
                Problem::error(
                    "yaml.duplicate-key",
                    pointer.clone(),
                    Some(span.start),
                    messages::duplicate_key(),
                )
                .with_related(pointer, Some(first), messages::duplicate_key_note()),
            );
            self.set_refused_key(Some(value.to_string()));
            return;
        }
        if let Some(refusal) = self.call_key_hook(&pointer, value, style, span) {
            self.problems
                .push(refusal_problem(refusal, pointer, span.start));
        }
        if let Some(Frame::Mapping { seen, state, .. }) = self.stack.last_mut() {
            seen.insert(value.to_string(), span.start);
            *state = MapState::ExpectValue {
                key: Some((value.to_string(), span)),
                segment: Some(value.to_string()),
            };
        }
    }

    fn call_key_hook(
        &mut self,
        pointer: &str,
        value: &str,
        style: ScalarStyle,
        span: Span,
    ) -> Option<Refusal> {
        let hook = self.hook.take()?;
        let mut keys = self.keys();
        keys.push(value);
        let site = ScalarSite {
            pointer,
            keys: &keys,
            text: value,
            style,
            span,
        };
        let outcome = hook.key(&site);
        drop(keys);
        self.hook = Some(hook);
        outcome.err()
    }

    fn scalar_value(&mut self, value: String, style: ScalarStyle, span: Span) -> Node {
        let resolved = if style == ScalarStyle::Plain {
            resolve_plain(&value)
        } else {
            Resolved::String
        };
        let node_value = match resolved {
            Resolved::Null => NodeValue::Null,
            Resolved::Bool(value) => NodeValue::Bool(value),
            Resolved::Integer(value) => NodeValue::Integer(value),
            Resolved::Float(value) => NodeValue::Float(value),
            Resolved::Ambiguous => {
                self.problem_here(
                    "yaml.ambiguous-number",
                    span.start,
                    messages::ambiguous_number(),
                );
                NodeValue::Null
            }
            Resolved::IntegerOutOfRange | Resolved::FloatOutOfRange => {
                // Kept as its text: decoding refuses it in the words of the
                // member that reads it, such as "quote it" in a text member.
                let integer = resolved == Resolved::IntegerOutOfRange;
                self.unrepresentable.push(Problem::error(
                    "config.out-of-range",
                    self.pointer(),
                    Some(span.start),
                    messages::literal_out_of_range(integer),
                ));
                NodeValue::String(Text {
                    text: value,
                    style,
                    substituted: false,
                })
            }
            Resolved::String if holds_control_character(&value) => {
                // Refused as written, before any hook sees it.
                self.problem_here(
                    "yaml.control-character",
                    span.start,
                    messages::control_character(),
                );
                NodeValue::String(Text {
                    text: String::new(),
                    style,
                    substituted: false,
                })
            }
            Resolved::String => {
                let pointer = self.pointer();
                match self.call_value_hook(&pointer, &value, style, span) {
                    Ok(Some(replacement)) => NodeValue::String(Text {
                        text: replacement,
                        style,
                        substituted: true,
                    }),
                    Ok(None) => NodeValue::String(Text {
                        text: value,
                        style,
                        substituted: false,
                    }),
                    Err(refusal) => {
                        self.problems
                            .push(refusal_problem(refusal, pointer, span.start));
                        NodeValue::String(Text {
                            text: String::new(),
                            style,
                            substituted: false,
                        })
                    }
                }
            }
        };
        Node {
            value: node_value,
            span,
        }
    }

    fn call_value_hook(
        &mut self,
        pointer: &str,
        value: &str,
        style: ScalarStyle,
        span: Span,
    ) -> Result<Option<String>, Refusal> {
        let Some(hook) = self.hook.take() else {
            return Ok(None);
        };
        let keys = self.keys();
        let site = ScalarSite {
            pointer,
            keys: &keys,
            text: value,
            style,
            span,
        };
        let outcome = hook.value(&site);
        drop(keys);
        self.hook = Some(hook);
        outcome
    }

    /// An alias stands where a node would be; its value is dropped.
    fn insert_refused(&mut self, span: Span) {
        if self.expects_key() {
            self.set_refused_key(None);
        } else {
            self.insert_value(Node {
                value: NodeValue::Null,
                span,
            });
        }
    }

    fn insert_value(&mut self, node: Node) {
        match self.stack.last_mut() {
            None => {
                if self.root.is_none() {
                    self.root = Some(node);
                }
            }
            Some(Frame::Sequence { items, .. }) => items.push(node),
            Some(Frame::Mapping { entries, state, .. }) => {
                if let MapState::ExpectValue {
                    key: Some((key, key_span)),
                    ..
                } = std::mem::replace(state, MapState::ExpectKey)
                {
                    entries.push(Entry {
                        key,
                        key_span,
                        value: node,
                    });
                }
            }
        }
    }

    fn classify_syntax_error(&self, error: &ScanError) -> Problem {
        let info = error.info();
        let marker = error.marker();
        let at = position(marker);
        let pointer = self.pointer();
        let lines: Vec<&str> = self
            .text
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .collect();

        // A tab the parser names may indent the line after its marker. Any
        // other error blames a tab only when it indents the error's own line
        // up to the error's column.
        let parser_names_a_tab = info.contains("tab");
        let leading_tab = if parser_names_a_tab {
            [at.line, at.line + 1]
                .into_iter()
                .find_map(|line| leading_tab_position(&lines, line))
        } else {
            leading_tab_position(&lines, at.line).filter(|tab| tab.column <= at.column)
        };
        if parser_names_a_tab || leading_tab.is_some() {
            let tab = leading_tab
                .or_else(|| tab_at_or_after(&lines, at))
                .unwrap_or(at);
            return Problem::error(
                "yaml.tab-indentation",
                pointer,
                Some(tab),
                messages::tab_indentation(),
            );
        }
        if info.contains("quoted scalar")
            && (info.contains("escape") || info.contains("hexadecimal"))
        {
            return Problem::error(
                "yaml.invalid-escape",
                pointer,
                Some(at),
                messages::invalid_escape(),
            );
        }
        if info.starts_with("invalid trailing content after") {
            return Problem::error(
                "yaml.text-after-quote",
                pointer,
                Some(at),
                messages::text_after_quote(closing_quote_before(&lines, at)),
            );
        }
        if info.contains("quoted scalar") {
            return Problem::error(
                "yaml.unclosed-quote",
                pointer,
                Some(at),
                messages::unclosed_quote(),
            );
        }
        if info.contains("mapping values are not allowed") {
            let line = lines.get(at.line.saturating_sub(1)).copied().unwrap_or("");
            let before: String = line.chars().take(at.column.saturating_sub(1)).collect();
            if before.contains(": ") || before.contains(":\t") {
                return Problem::error(
                    "yaml.colon-in-plain-value",
                    pointer,
                    Some(at),
                    messages::colon_in_plain_value(),
                );
            }
            return Problem::error(
                "yaml.syntax",
                pointer,
                Some(at),
                messages::misplaced_colon(),
            );
        }
        if info == "':' must be followed by a valid YAML whitespace" {
            // The parser accepts a tab after `:` before a quoted or bracketed
            // value, and refuses it before any other.
            return Problem::error(
                "yaml.syntax",
                pointer,
                Some(tab_after_colon(&lines, at).unwrap_or(at)),
                messages::tab_after_colon(),
            );
        }
        if info == "recursion limit exceeded" {
            // The scanner's own flow nesting bound, reached while it looks
            // ahead past the reader's bound.
            return Problem::error(
                "yaml.too-deep",
                pointer,
                Some(at),
                messages::too_deep(MAXIMUM_DEPTH),
            );
        }
        if info.contains("anchor or alias") || info.contains("unknown anchor") {
            let (code, position) = self.anchor_or_alias_at(marker, at);
            let text = if code == "yaml.anchor" {
                messages::anchor()
            } else {
                messages::alias()
            };
            return Problem::error(code, pointer, Some(position), text);
        }
        let remaining_blank = self
            .text
            .chars()
            .skip(marker.index())
            .all(char::is_whitespace);
        if remaining_blank {
            return Problem::error(
                "yaml.unexpected-end",
                pointer,
                Some(at),
                messages::unexpected_end(self.open_flow_bracket()),
            );
        }
        // Every parser message is static text except the one that names an
        // unexpected character, which could carry an input byte.
        let note = (!info.starts_with("unexpected character")).then_some(info);
        Problem::error(
            "yaml.syntax",
            pointer,
            Some(at),
            messages::syntax(note, self.open_flow_bracket()),
        )
    }

    fn anchor_or_alias_at(&self, marker: &Marker, at: Position) -> (&'static str, Position) {
        let index = marker.index();
        let mut chars = self.text.chars().skip(index.saturating_sub(1));
        let before = if index > 0 { chars.next() } else { None };
        let here = if index > 0 {
            chars.next()
        } else {
            self.text.chars().next()
        };
        match (before, here) {
            (_, Some('&')) => ("yaml.anchor", at),
            (_, Some('*')) => ("yaml.alias", at),
            (Some('&'), _) => (
                "yaml.anchor",
                Position {
                    line: at.line,
                    column: at.column.saturating_sub(1).max(1),
                },
            ),
            (Some('*'), _) => (
                "yaml.alias",
                Position {
                    line: at.line,
                    column: at.column.saturating_sub(1).max(1),
                },
            ),
            _ => ("yaml.alias", at),
        }
    }

    /// The innermost open collection, when it was opened with a bracket.
    fn open_flow_bracket(&self) -> Option<(char, usize)> {
        let (start, start_index) = match self.stack.last()? {
            Frame::Sequence {
                start, start_index, ..
            }
            | Frame::Mapping {
                start, start_index, ..
            } => (*start, *start_index),
        };
        match self.text.chars().nth(start_index)? {
            bracket @ ('[' | '{') => Some((bracket, start.line)),
            _ => None,
        }
    }
}

fn leading_tab_position(lines: &[&str], line: usize) -> Option<Position> {
    let text = lines.get(line.checked_sub(1)?)?;
    for (offset, c) in text.chars().enumerate() {
        match c {
            ' ' => continue,
            '\t' => {
                return Some(Position {
                    line,
                    column: offset + 1,
                })
            }
            _ => return None,
        }
    }
    None
}

/// The quote that closed the value before the text at `at`.
fn closing_quote_before(lines: &[&str], at: Position) -> Option<char> {
    let text = lines.get(at.line.checked_sub(1)?)?;
    text.chars()
        .take(at.column.saturating_sub(1))
        .filter(|c| !matches!(c, ' ' | '\t'))
        .last()
        .filter(|c| matches!(c, '\'' | '"'))
}

/// The tab right after the last `:` before `at` on its line.
fn tab_after_colon(lines: &[&str], at: Position) -> Option<Position> {
    let text = lines.get(at.line.checked_sub(1)?)?;
    let before: Vec<char> = text.chars().take(at.column.saturating_sub(1)).collect();
    let colon = before.iter().rposition(|c| *c == ':')?;
    (before.get(colon + 1) == Some(&'\t')).then_some(Position {
        line: at.line,
        column: colon + 2,
    })
}

fn tab_at_or_after(lines: &[&str], at: Position) -> Option<Position> {
    let text = lines.get(at.line.checked_sub(1)?)?;
    text.chars()
        .enumerate()
        .skip(at.column.saturating_sub(1))
        .find(|(_, c)| *c == '\t')
        .map(|(offset, _)| Position {
            line: at.line,
            column: offset + 1,
        })
}

fn convert_style(style: EventStyle) -> ScalarStyle {
    match style {
        EventStyle::Plain => ScalarStyle::Plain,
        EventStyle::SingleQuoted => ScalarStyle::SingleQuoted,
        EventStyle::DoubleQuoted => ScalarStyle::DoubleQuoted,
        EventStyle::Literal => ScalarStyle::Literal,
        EventStyle::Folded => ScalarStyle::Folded,
    }
}

/// Whether text holds a control character (C0, DEL, or C1, NEL included)
/// other than tab, line feed, and carriage return, written raw or as an
/// escape (CFG-VAL-1).
fn holds_control_character(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

fn refusal_problem(refusal: Refusal, pointer: String, at: Position) -> Problem {
    Problem {
        severity: crate::diagnostic::Severity::Error,
        code: refusal.code,
        pointer,
        position: Some(at),
        message: refusal.message,
        action: refusal.suggested_action,
        related: Vec::new(),
    }
}
