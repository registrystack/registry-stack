// SPDX-License-Identifier: Apache-2.0
//! Decoding the document tree into Rust types with serde, keeping every
//! error at the node it concerns (CFG-SCHEMA-8, CFG-DIAG-5).
//!
//! The decoder refuses unknown keys in every struct whatever its serde
//! attributes say, records unknown and removed keys and carries on, and stops
//! at the first other error. An error a visitor reports without a position
//! is placed at the node the visitor was decoding; the visitor's own text is
//! never passed through, only the reader's sentences.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

use serde::de::{self, DeserializeSeed, Visitor};
use serde::forward_to_deserialize_any;

use crate::messages::{self, Found, NullPlace, Problem, EXPECT_DATA_LITERAL};
use crate::node::{
    escape_pointer_segment, Entry, Node, NodeValue, Position, ScalarStyle, Span, Unrepresentable,
};
use crate::scalar::{resolve_plain, Resolved};

/// The newtype name an internally tagged union asks for, followed by its tag
/// key. [`crate::tagged_union!`] writes the same text as a literal.
pub(crate) const TAGGED_PREFIX: &str = "\0registry-platform-yaml/tagged/";
/// The newtype name a node-kind union asks for, followed by the shapes it
/// accepts. [`crate::shape_union!`] writes the same text as a literal.
pub(crate) const SHAPE_PREFIX: &str = "\0registry-platform-yaml/shape/";
/// The newtype name [`crate::DataLiteral`] asks for: the one position where
/// null is a value.
pub(crate) const DATA_LITERAL: &str = "\0registry-platform-yaml/data-literal";
/// The newtype name the bounded integers ask for. Their visitor's
/// `expecting` text carries the bounds.
pub(crate) const BOUNDED: &str = "\0registry-platform-yaml/bounded";
pub(crate) const BOUNDED_EXPECTING: &str = "a whole number from ";

/// A field renamed to a name starting with this prefix holds a platform
/// shared block: the block's members sit beside the host's own, in the same
/// mapping, and keep their positions. See the crate documentation.
pub const SHARED_BLOCK_PREFIX: &str = "registry-platform-yaml/shared-block/";

const PROTOCOL: &str = "registry-platform-yaml";
const SEPARATOR: char = '\u{1f}';
const PROBE_VARIANT: &str = "\u{0}registry-platform-yaml/no-such-variant";

/// An error a product's own `Deserialize` or `TryFrom` code reports, so the
/// reader words it as one of its own diagnostics at the node being decoded.
///
/// A `Deserialize` impl returns `invalid.into_error()`; a `TryFrom` used
/// through `#[serde(try_from = "...")]` returns the `Invalid` itself. Both
/// reach the reader through [`serde::de::Error::custom`], which a product may
/// also call directly.
///
/// The texts are `&'static str`, so they cannot carry a value read from the
/// file (CFG-SEC-3). Plain `Display` (`{}`) writes only the sentence, which
/// is what a deserializer other than the reader shows; the reader reads the
/// whole error through the alternate form (`{:#}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid(InvalidKind);

#[derive(Clone, Debug, PartialEq, Eq)]
enum InvalidKind {
    Expected {
        expected: &'static str,
        action: &'static str,
    },
    OutOfRange {
        minimum: i128,
        maximum: i128,
    },
    DuplicateItem {
        first: usize,
        second: usize,
    },
    DuplicateId {
        first: usize,
        second: usize,
    },
}

impl Invalid {
    /// The value has the right shape but is not valid. `expected` completes
    /// "expected ..."; `suggested_action` is a sentence naming the fix.
    pub const fn expected(expected: &'static str, suggested_action: &'static str) -> Invalid {
        Invalid(InvalidKind::Expected {
            expected,
            action: suggested_action,
        })
    }

    /// An integer outside its bounds.
    pub fn out_of_range(minimum: impl Into<i128>, maximum: impl Into<i128>) -> Invalid {
        Invalid(InvalidKind::OutOfRange {
            minimum: minimum.into(),
            maximum: maximum.into(),
        })
    }

    pub(crate) fn duplicate_item(first: usize, second: usize) -> Invalid {
        Invalid(InvalidKind::DuplicateItem { first, second })
    }

    pub(crate) fn duplicate_id(first: usize, second: usize) -> Invalid {
        Invalid(InvalidKind::DuplicateId { first, second })
    }

    /// This error as any deserializer's error type:
    /// `serde::de::Error::custom(self)`. A `Deserialize` impl returns
    /// `Err(Invalid::expected(..).into_error())`.
    pub fn into_error<E: de::Error>(self) -> E {
        E::custom(self)
    }
}

/// `{}` writes the sentence only. `{:#}` adds the fields the reader reads
/// back, separated by U+001F; only the reader asks for it.
impl fmt::Display for Invalid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            InvalidKind::Expected { expected, .. } => write!(formatter, "expected {expected}")?,
            InvalidKind::OutOfRange { minimum, maximum } => write!(
                formatter,
                "expected a whole number from {minimum} to {maximum}"
            )?,
            InvalidKind::DuplicateItem { first, second } => {
                write!(formatter, "item {second} repeats item {first}")?
            }
            InvalidKind::DuplicateId { first, second } => {
                write!(formatter, "item {second} repeats the id of item {first}")?
            }
        }
        if !formatter.alternate() {
            return Ok(());
        }
        let s = SEPARATOR;
        match &self.0 {
            InvalidKind::Expected { expected, action } => {
                write!(
                    formatter,
                    "{s}{PROTOCOL}{s}expected{s}{expected}{s}{action}"
                )
            }
            InvalidKind::OutOfRange { minimum, maximum } => write!(
                formatter,
                "{s}{PROTOCOL}{s}out-of-range{s}{minimum}{s}{maximum}"
            ),
            InvalidKind::DuplicateItem { first, second } => write!(
                formatter,
                "{s}{PROTOCOL}{s}duplicate-item{s}{first}{s}{second}"
            ),
            InvalidKind::DuplicateId { first, second } => write!(
                formatter,
                "{s}{PROTOCOL}{s}duplicate-id{s}{first}{s}{second}"
            ),
        }
    }
}

impl std::error::Error for Invalid {}

/// [`Invalid`] read back from a custom error's text.
enum Protocol {
    Expected { expected: String, action: String },
    OutOfRange { minimum: i128, maximum: i128 },
    DuplicateItem { first: usize, second: usize },
    DuplicateId { first: usize, second: usize },
}

fn parse_protocol(text: &str) -> Option<Protocol> {
    let parts: Vec<&str> = text.split(SEPARATOR).collect();
    let [_, protocol, kind, first, second] = parts.as_slice() else {
        return None;
    };
    if *protocol != PROTOCOL {
        return None;
    }
    match *kind {
        "expected" => Some(Protocol::Expected {
            expected: first.to_string(),
            action: second.to_string(),
        }),
        "out-of-range" => Some(Protocol::OutOfRange {
            minimum: first.parse().ok()?,
            maximum: second.parse().ok()?,
        }),
        "duplicate-item" => Some(Protocol::DuplicateItem {
            first: first.parse().ok()?,
            second: second.parse().ok()?,
        }),
        "duplicate-id" => Some(Protocol::DuplicateId {
            first: first.parse().ok()?,
            second: second.parse().ok()?,
        }),
        _ => None,
    }
}

/// serde's derived code reports an unknown key it found in a flattened
/// struct with this text; it is the derive's own wording, not a nested
/// deserializer's message.
fn serde_unknown_field(text: &str) -> Option<&str> {
    text.strip_prefix("unknown field `")?.strip_suffix('`')
}

// ----- the error type -----

/// The error the decoder's serde traits use. It reaches callers only as a
/// [`crate::Report`].
pub(crate) struct Error(Box<Inner>);

enum Inner {
    Located(Problem),
    Unlocated(Kind),
}

#[derive(Debug)]
enum Kind {
    InvalidType(String),
    InvalidValue(String),
    InvalidLength(String),
    UnknownVariant(&'static [&'static str], Option<messages::Suggestion>),
    UnknownField(String, &'static [&'static str]),
    MissingField(&'static str),
    DuplicateField(&'static str),
    Custom(String),
}

impl Error {
    fn located(problem: Problem) -> Error {
        Error(Box::new(Inner::Located(problem)))
    }

    fn unlocated(kind: Kind) -> Error {
        Error(Box::new(Inner::Unlocated(kind)))
    }

    /// The problem, placed at `node` when the error has no position yet.
    pub(crate) fn into_problem(self, node: &Node, path: &str) -> Problem {
        match *self.0 {
            Inner::Located(problem) => problem,
            Inner::Unlocated(kind) => {
                let site = Site {
                    node,
                    path: path.to_string(),
                    key_span: None,
                    member: None,
                    place: Place::Root,
                };
                describe(&site, kind, false)
            }
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Never a value: a located error shows the reader's own message, and an
/// unlocated one only its kind.
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            Inner::Located(problem) => formatter.write_str(&problem.message),
            Inner::Unlocated(kind) => formatter.write_str(match kind {
                Kind::InvalidType(_) => "invalid type",
                Kind::InvalidValue(_) | Kind::Custom(_) => "invalid value",
                Kind::InvalidLength(_) => "invalid length",
                Kind::UnknownVariant(..) => "unknown variant",
                Kind::UnknownField(..) => "unknown key",
                Kind::MissingField(_) => "missing member",
                Kind::DuplicateField(_) => "duplicate member",
            }),
        }
    }
}

impl std::error::Error for Error {}

impl de::Error for Error {
    /// The alternate form carries an [`Invalid`]'s fields; any other text is
    /// never shown.
    fn custom<T: fmt::Display>(message: T) -> Error {
        Error::unlocated(Kind::Custom(format!("{message:#}")))
    }

    fn invalid_type(_: de::Unexpected<'_>, expected: &dyn de::Expected) -> Error {
        Error::unlocated(Kind::InvalidType(expected.to_string()))
    }

    fn invalid_value(_: de::Unexpected<'_>, expected: &dyn de::Expected) -> Error {
        Error::unlocated(Kind::InvalidValue(expected.to_string()))
    }

    fn invalid_length(_: usize, expected: &dyn de::Expected) -> Error {
        Error::unlocated(Kind::InvalidLength(expected.to_string()))
    }

    fn unknown_variant(variant: &str, expected: &'static [&'static str]) -> Error {
        // Only the accepted name the value is close to is kept, never the
        // value itself.
        let suggestion = messages::suggest(variant, expected);
        Error::unlocated(Kind::UnknownVariant(expected, suggestion))
    }

    fn unknown_field(field: &str, expected: &'static [&'static str]) -> Error {
        Error::unlocated(Kind::UnknownField(field.to_string(), expected))
    }

    fn missing_field(field: &'static str) -> Error {
        Error::unlocated(Kind::MissingField(field))
    }

    fn duplicate_field(field: &'static str) -> Error {
        Error::unlocated(Kind::DuplicateField(field))
    }
}

// ----- decoding state -----

/// State shared by one decode.
pub(crate) struct Ctx {
    /// Unknown and removed keys, recorded while decoding continues.
    sink: RefCell<Vec<Problem>>,
    /// Pointers of keys already reported as removed.
    removed: HashSet<String>,
    /// How many lists and mappings a self-describing visitor has taken
    /// whole. An error that arrives after one did may concern any node
    /// inside it.
    buffered: Cell<u64>,
    /// How members refused the unrepresentable numbers they read, in their
    /// own words (see `Node::unrepresentable`).
    claims: RefCell<Vec<Problem>>,
}

impl Ctx {
    pub(crate) fn new(removed: Vec<Problem>) -> Ctx {
        Ctx {
            removed: removed
                .iter()
                .map(|problem| problem.pointer.clone())
                .collect(),
            sink: RefCell::new(removed),
            buffered: Cell::new(0),
            claims: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn take_claims(&self) -> Vec<Problem> {
        self.claims.take()
    }

    pub(crate) fn into_problems(self) -> Vec<Problem> {
        self.sink.into_inner()
    }

    fn record(&self, problem: Problem) {
        self.sink.borrow_mut().push(problem);
    }
}

/// Where a node sits, for the null message and the envelope members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    Root,
    Member,
    Item,
}

/// What an error needs to be placed: the node, its pointer, the key that
/// names it, and the nearest member key (for the unit word).
#[derive(Clone)]
struct Site<'a> {
    node: &'a Node,
    path: String,
    key_span: Option<Span>,
    member: Option<&'a str>,
    place: Place,
}

impl<'a> Site<'a> {
    fn value_at(&self) -> Option<Position> {
        Some(self.node.span.start)
    }

    /// A missing member is reported at the key of the mapping that lacks it,
    /// or where the mapping starts when no key names it (CFG-DIAG-1).
    fn mapping_at(&self) -> Option<Position> {
        Some(
            self.key_span
                .map_or(self.node.span.start, |span| span.start),
        )
    }

    fn child_path(&self, segment: &str) -> String {
        format!("{}/{}", self.path, escape_pointer_segment(segment))
    }

    fn problem(&self, code: &str, text: messages::Text) -> Problem {
        let text = if HASH_HINT_CODES.contains(&code) && holds_unspaced_hash(self.node) {
            messages::with_hash_hint(text)
        } else {
            text
        };
        Problem::error(code, self.path.clone(), self.value_at(), text)
    }
}

/// The codes of a scalar value that failed to decode, whose fix names the
/// `#` an unquoted value holds with no space before it.
const HASH_HINT_CODES: &[&str] = &[
    "config.expected-integer",
    "config.expected-number",
    "config.expected-boolean",
    "config.unknown-variant",
    "config.invalid-value",
];

/// An unquoted value holding a `#` with no space before it: YAML read the
/// `#` and what follows as part of the value, where the author may have
/// meant a comment. Substituted text is left out, since its `#` may come
/// from the environment and not from the file.
fn holds_unspaced_hash(node: &Node) -> bool {
    let NodeValue::String(text) = &node.value else {
        return false;
    };
    text.style == ScalarStyle::Plain
        && !text.substituted
        && text.text.char_indices().any(|(index, character)| {
            character == '#'
                && text.text[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|before| !before.is_whitespace())
        })
}

/// The platform shared blocks a host struct holds, and the keys they took.
#[derive(Default)]
struct Blocks {
    claimed: RefCell<HashSet<String>>,
    fields: RefCell<Vec<&'static str>>,
}

/// Deserializes one node.
#[derive(Clone)]
pub(crate) struct NodeDe<'a> {
    site: Site<'a>,
    ctx: &'a Ctx,
    /// The tag key of an internally tagged union, not a member of the
    /// variant.
    exclude: Option<&'static str>,
    /// Set when this node is decoded as a shared block of its host.
    view: Option<Rc<Blocks>>,
    bounds: Option<(i128, i128)>,
    allow_null: bool,
}

impl<'a> NodeDe<'a> {
    pub(crate) fn new(
        node: &'a Node,
        path: String,
        key_span: Option<Span>,
        member: Option<&'a str>,
        place: Place,
        ctx: &'a Ctx,
    ) -> NodeDe<'a> {
        NodeDe {
            site: Site {
                node,
                path,
                key_span,
                member,
                place,
            },
            ctx,
            exclude: None,
            view: None,
            bounds: None,
            allow_null: false,
        }
    }

    fn child(&self, entry: &'a Entry) -> NodeDe<'a> {
        NodeDe::new(
            &entry.value,
            self.site.child_path(&entry.key),
            Some(entry.key_span),
            Some(&entry.key),
            Place::Member,
            self.ctx,
        )
    }

    fn item(&self, index: usize, node: &'a Node) -> NodeDe<'a> {
        NodeDe::new(
            node,
            format!("{}/{}", self.site.path, index),
            None,
            self.site.member,
            Place::Item,
            self.ctx,
        )
    }

    /// Run one deserializer method, placing any error that has no position
    /// yet at this node.
    fn run<T>(
        self,
        accepts_view: bool,
        body: impl FnOnce(&NodeDe<'a>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.view.is_some() && !accepts_view {
            return Err(Error::located(self.site.problem(
                "config.invalid-type",
                messages::developer_misuse("a shared block must be a struct"),
            )));
        }
        let before = self.ctx.buffered.get();
        let result = body(&self);
        result.map_err(|error| match *error.0 {
            Inner::Located(problem) => Error::located(problem),
            Inner::Unlocated(kind) => {
                let buffered = self.ctx.buffered.get() != before;
                Error::located(describe(&self.site, kind, buffered))
            }
        })
    }

    /// Decode this node with `seed`, placing at this node an error raised
    /// after its deserializer returned, such as a `try_from` conversion or a
    /// set's duplicate check.
    fn seed<'de, S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, Error> {
        let site = self.site.clone();
        let before = self.ctx.buffered.get();
        let buffered = &self.ctx.buffered;
        let result = seed.deserialize(self);
        result.map_err(|error| match *error.0 {
            Inner::Located(problem) => Error::located(problem),
            Inner::Unlocated(kind) => {
                Error::located(describe(&site, kind, buffered.get() != before))
            }
        })
    }

    fn fail(&self, code: &str, text: messages::Text) -> Error {
        Error::located(self.site.problem(code, text))
    }

    /// Refuse an unrepresentable number this member read, in its words.
    fn claim(&self, code: &str, text: messages::Text) -> Error {
        let problem = self.site.problem(code, text);
        self.ctx.claims.borrow_mut().push(problem.clone());
        Error::located(problem)
    }

    fn null_error(&self, block: bool) -> Error {
        let place = match self.site.place {
            Place::Item => NullPlace::Item,
            _ if block => NullPlace::Block,
            _ => NullPlace::Member,
        };
        self.fail("config.null-value", messages::null_value(place))
    }

    fn found(&self) -> Found {
        found(self.site.node)
    }

    fn unit(&self) -> Option<&'static str> {
        messages::unit_word(self.site.member)
    }

    fn integer(&self, type_minimum: i128, type_maximum: i128) -> Result<i128, Error> {
        let (minimum, maximum) = match self.bounds {
            Some((low, high)) => (low.max(type_minimum), high.min(type_maximum)),
            None => (type_minimum, type_maximum),
        };
        let bounds = messages::Bounds::new(minimum, maximum);
        match &self.site.node.value {
            NodeValue::Integer(value) if *value < minimum || *value > maximum => Err(self.fail(
                "config.out-of-range",
                messages::integer_out_of_range(self.unit(), &bounds),
            )),
            NodeValue::Integer(value) => Ok(*value),
            NodeValue::Null => Err(self.null_error(false)),
            _ => match self.site.node.unrepresentable() {
                Some(Unrepresentable::Integer) => Err(self.claim(
                    "config.out-of-range",
                    messages::integer_out_of_range(self.unit(), &bounds),
                )),
                _ => Err(self.fail(
                    "config.expected-integer",
                    messages::expected_integer(self.found(), self.unit(), &bounds),
                )),
            },
        }
    }

    fn number(&self) -> Result<f64, Error> {
        match &self.site.node.value {
            NodeValue::Integer(value) => Ok(*value as f64),
            NodeValue::Float(value) => Ok(*value),
            NodeValue::Null => Err(self.null_error(false)),
            _ => Err(self.fail(
                "config.expected-number",
                messages::expected_number(self.found(), self.unit()),
            )),
        }
    }

    fn text(&self) -> Result<&'a str, Error> {
        match &self.site.node.value {
            NodeValue::String(text) => match self.site.node.unrepresentable() {
                None => Ok(&text.text),
                Some(literal) => {
                    let found = match literal {
                        Unrepresentable::Integer => Found::Integer,
                        Unrepresentable::Number => Found::Number,
                    };
                    Err(self.claim("config.expected-string", messages::expected_string(found)))
                }
            },
            NodeValue::Null => Err(self.null_error(false)),
            _ => Err(self.fail(
                "config.expected-string",
                messages::expected_string(self.found()),
            )),
        }
    }

    fn mapping(&self) -> Result<&'a [Entry], Error> {
        match &self.site.node.value {
            NodeValue::Mapping(entries) => Ok(entries),
            NodeValue::Null => Err(self.null_error(true)),
            _ => Err(self.fail(
                "config.invalid-type",
                messages::expected_collection(false, self.found()),
            )),
        }
    }

    fn sequence(&self) -> Result<&'a [Node], Error> {
        match &self.site.node.value {
            NodeValue::Sequence(items) => Ok(items),
            NodeValue::Null => Err(self.null_error(false)),
            _ => Err(self.fail(
                "config.invalid-type",
                messages::expected_collection(true, self.found()),
            )),
        }
    }

    fn is_removed(&self, pointer: &str) -> bool {
        !self.ctx.removed.is_empty() && self.ctx.removed.contains(pointer)
    }

    fn visit_items<'de, V: Visitor<'de>>(
        &self,
        items: &'a [Node],
        visitor: V,
        exact: Option<usize>,
    ) -> Result<V::Value, Error> {
        if let Some(length) = exact {
            if items.len() != length {
                let expected = format!(
                    "exactly {length} {}",
                    if length == 1 { "item" } else { "items" }
                );
                return Err(self.fail("config.invalid-length", messages::invalid_length(&expected)));
            }
        }
        let mut access = SeqAccess {
            parent: self,
            items,
            index: 0,
        };
        let value = visitor.visit_seq(&mut access)?;
        if access.index < items.len() {
            let expected = format!("at most {} items", access.index);
            let item = &items[access.index];
            return Err(Error::located(Problem::error(
                "config.invalid-length",
                format!("{}/{}", self.site.path, access.index),
                Some(item.span.start),
                messages::invalid_length(&expected),
            )));
        }
        Ok(value)
    }
}

/// What the node holds, in the words messages may use. Never the value.
pub(crate) fn found(node: &Node) -> Found {
    match &node.value {
        NodeValue::Null => Found::Null,
        NodeValue::Bool(_) => Found::Boolean,
        NodeValue::Integer(_) => Found::Integer,
        NodeValue::Float(_) => Found::Number,
        NodeValue::Sequence(_) => Found::List,
        NodeValue::Mapping(_) => Found::Mapping,
        NodeValue::String(text) if text.substituted => Found::Substituted,
        NodeValue::String(text) if text.style == ScalarStyle::Plain => plain_found(&text.text),
        NodeValue::String(text) => match resolve_plain(&text.text) {
            Resolved::Integer(_)
            | Resolved::Float(_)
            | Resolved::IntegerOutOfRange
            | Resolved::FloatOutOfRange => Found::QuotedNumber,
            Resolved::Bool(_) => Found::QuotedBoolean,
            _ => Found::QuotedText,
        },
    }
}

fn plain_found(text: &str) -> Found {
    if matches!(
        text.to_ascii_lowercase().as_str(),
        "yes" | "no" | "on" | "off" | "y" | "n"
    ) {
        return Found::YesNo;
    }
    let unsigned = text.strip_prefix(['-', '+']).unwrap_or(text);
    let digits = unsigned.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Found::PlainText;
    }
    let rest = &unsigned[digits..];
    if !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        Found::UnitSuffixed
    } else {
        Found::DigitText
    }
}

/// The expected text a visitor gave, in the reader's words, or `None` when
/// the reader cannot vouch for it (CFG-SEC-3).
///
/// A visitor's `expecting` text is shown only when it comes from serde's own
/// primitives or from the reader's types, whose texts are fixed. Any other
/// visitor may have formatted part of the value into it, so its text gives
/// way to the generic sentence.
fn safe_expected(expected: &str) -> Option<String> {
    let translated = match expected {
        "map" | "a map" => Some("a mapping"),
        "a sequence" | "sequence" => Some("a list"),
        "a string" | "string" | "a borrowed string" | "a string slice" => Some("text"),
        "a boolean" | "bool" => Some("true or false"),
        "a character" | "char" => Some("a single character"),
        "unit" | "unit value" => Some("an empty mapping"),
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128"
        | "isize" | "an integer" => Some("a whole number"),
        "a nonzero u8" | "a nonzero u16" | "a nonzero u32" | "a nonzero u64" | "a nonzero u128"
        | "a nonzero usize" | "a nonzero i8" | "a nonzero i16" | "a nonzero i32"
        | "a nonzero i64" | "a nonzero i128" | "a nonzero isize" => {
            Some("a whole number other than 0")
        }
        "f32" | "f64" | "a number" => Some("a number"),
        "a key" => Some("a key"),
        _ => None,
    };
    if let Some(translated) = translated {
        return Some(translated.to_string());
    }
    if expected.starts_with("struct ") || expected.starts_with("a struct") {
        return Some("a mapping".to_string());
    }
    if expected.starts_with("tuple") || expected.starts_with("a tuple") {
        return Some("a list".to_string());
    }
    if expected == EXPECT_DATA_LITERAL {
        return Some(EXPECT_DATA_LITERAL.to_string());
    }
    if let Some((minimum, maximum)) = parse_bounds(expected) {
        return Some(format!("{BOUNDED_EXPECTING}{minimum} to {maximum}"));
    }
    None
}

/// Turn an error a visitor raised at `site` into the reader's problem.
fn describe(site: &Site<'_>, kind: Kind, buffered: bool) -> Problem {
    let node = site.node;
    let approximate =
        |code: &str, expected: Option<&str>| site.problem(code, messages::approximate(expected));
    match kind {
        Kind::MissingField(field) => Problem::error(
            "config.missing-key",
            site.path.clone(),
            site.mapping_at(),
            messages::missing_key(field),
        ),
        Kind::DuplicateField(field) => Problem::error(
            "config.duplicate-key",
            site.path.clone(),
            site.mapping_at(),
            messages::duplicate_member(field),
        ),
        Kind::UnknownField(name, expected) => {
            let visible: Vec<&str> = expected
                .iter()
                .copied()
                .filter(|field| !field.starts_with(SHARED_BLOCK_PREFIX))
                .collect();
            unknown_key_problem(site, &name, Some(&visible))
                .unwrap_or_else(|| approximate("config.unknown-key", None))
        }
        Kind::UnknownVariant(expected, suggestion) => {
            if buffered {
                let accepted = format!("one of {}", messages::list(expected));
                approximate("config.unknown-variant", Some(&accepted))
            } else {
                // A hint about substituted text would reveal part of it.
                let suggestion = suggestion.filter(|_| found(node) != Found::Substituted);
                site.problem(
                    "config.unknown-variant",
                    messages::unknown_variant(expected, suggestion),
                )
            }
        }
        Kind::InvalidType(expected) => {
            let expected = safe_expected(&expected);
            if buffered {
                approximate("config.invalid-type", expected.as_deref())
            } else {
                match expected {
                    Some(expected) => site.problem(
                        "config.invalid-type",
                        messages::invalid_type(&expected, found(node)),
                    ),
                    None => site.problem("config.invalid-type", messages::invalid_value_generic()),
                }
            }
        }
        Kind::InvalidValue(expected) => {
            let expected = safe_expected(&expected);
            if buffered {
                approximate("config.invalid-value", expected.as_deref())
            } else {
                match expected {
                    Some(expected) => site.problem(
                        "config.invalid-value",
                        messages::invalid_value(&expected, None),
                    ),
                    None => site.problem("config.invalid-value", messages::invalid_value_generic()),
                }
            }
        }
        Kind::InvalidLength(expected) => {
            let expected = safe_expected(&expected)
                .unwrap_or_else(|| "a different number of items".to_string());
            site.problem("config.invalid-length", messages::invalid_length(&expected))
        }
        Kind::Custom(text) => match parse_protocol(&text) {
            Some(Protocol::Expected { expected, action }) => {
                if buffered {
                    approximate("config.invalid-value", Some(&expected))
                } else {
                    site.problem(
                        "config.invalid-value",
                        messages::invalid_value(&expected, Some(&action)),
                    )
                }
            }
            Some(Protocol::OutOfRange { minimum, maximum }) => {
                let bounds = messages::Bounds::new(minimum, maximum);
                if buffered {
                    let expected = messages::whole_number(None, &bounds);
                    approximate("config.out-of-range", Some(&expected))
                } else {
                    site.problem(
                        "config.out-of-range",
                        messages::integer_out_of_range(messages::unit_word(site.member), &bounds),
                    )
                }
            }
            Some(Protocol::DuplicateItem { first, second }) => item_problem(
                site,
                "config.duplicate-item",
                first,
                second,
                false,
                messages::duplicate_item(first),
                messages::duplicate_item_note(),
            ),
            Some(Protocol::DuplicateId { first, second }) => item_problem(
                site,
                "config.duplicate-id",
                first,
                second,
                true,
                messages::duplicate_id("id", first),
                messages::duplicate_id_note(),
            ),
            None => match serde_unknown_field(&text)
                .and_then(|name| unknown_key_problem(site, name, None))
            {
                Some(problem) => problem,
                None if buffered => approximate("config.invalid-value", None),
                None => site.problem("config.invalid-value", messages::invalid_value_generic()),
            },
        },
    }
}

fn unknown_key_problem(site: &Site<'_>, name: &str, accepted: Option<&[&str]>) -> Option<Problem> {
    let entry = site.node.get(name)?;
    Some(Problem::error(
        "config.unknown-key",
        site.child_path(name),
        Some(entry.key_span.start),
        messages::unknown_key(name, accepted),
    ))
}

fn item_problem(
    site: &Site<'_>,
    code: &str,
    first: usize,
    second: usize,
    at_id: bool,
    text: messages::Text,
    note: &str,
) -> Problem {
    let NodeValue::Sequence(items) = &site.node.value else {
        return site.problem(code, text);
    };
    let place = |index: usize| -> (String, Option<Position>) {
        let path = format!("{}/{}", site.path, index);
        match items.get(index) {
            Some(item) if at_id => match item.get("id") {
                Some(entry) => (format!("{path}/id"), Some(entry.value.span.start)),
                None => (path, Some(item.span.start)),
            },
            Some(item) => (path, Some(item.span.start)),
            None => (path, None),
        }
    };
    let (path, at) = place(second);
    let (first_path, first_at) = place(first);
    Problem::error(code, path, at, text).with_related(first_path, first_at, note)
}

// ----- the deserializer -----

impl<'de, 'a> de::Deserializer<'de> for NodeDe<'a> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        // A visitor that takes a node whole may keep it and fail later, at
        // a node above, without its position: the count lets that error say
        // so. A scalar counts once taken, so its own error stays exact.
        let buffered = &self.ctx.buffered;
        let taken = || buffered.set(buffered.get() + 1);
        self.run(false, |de| {
            let value = match &de.site.node.value {
                NodeValue::Null if de.allow_null => visitor.visit_unit(),
                NodeValue::Null => Err(de.null_error(false)),
                NodeValue::Bool(value) => visitor.visit_bool(*value),
                NodeValue::Integer(value) => match u64::try_from(*value) {
                    Ok(unsigned) => visitor.visit_u64(unsigned),
                    Err(_) => visitor.visit_i64(i64::try_from(*value).unwrap_or(i64::MIN)),
                },
                NodeValue::Float(value) => visitor.visit_f64(*value),
                NodeValue::String(text) => visitor.visit_str(&text.text),
                NodeValue::Sequence(items) => {
                    taken();
                    return de.visit_items(items, visitor, None);
                }
                NodeValue::Mapping(entries) => {
                    taken();
                    return visitor.visit_map(MapAccess::new(de, entries));
                }
            }?;
            taken();
            Ok(value)
        })
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| match &de.site.node.value {
            NodeValue::Bool(value) => visitor.visit_bool(*value),
            NodeValue::Null => Err(de.null_error(false)),
            _ => Err(de.fail(
                "config.expected-boolean",
                messages::expected_boolean(de.found()),
            )),
        })
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(i8::MIN.into(), i8::MAX.into())?;
            visitor.visit_i8(value as i8)
        })
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(i16::MIN.into(), i16::MAX.into())?;
            visitor.visit_i16(value as i16)
        })
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(i32::MIN.into(), i32::MAX.into())?;
            visitor.visit_i32(value as i32)
        })
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(i64::MIN.into(), i64::MAX.into())?;
            visitor.visit_i64(value as i64)
        })
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(i64::MIN.into(), u64::MAX.into())?;
            visitor.visit_i128(value)
        })
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(0, u8::MAX.into())?;
            visitor.visit_u8(value as u8)
        })
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(0, u16::MAX.into())?;
            visitor.visit_u16(value as u16)
        })
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(0, u32::MAX.into())?;
            visitor.visit_u32(value as u32)
        })
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(0, u64::MAX.into())?;
            visitor.visit_u64(value as u64)
        })
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.integer(0, u64::MAX.into())?;
            visitor.visit_u128(value as u128)
        })
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let value = de.number()?;
            if value.abs() > f64::from(f32::MAX) {
                return Err(de.fail(
                    "config.out-of-range",
                    messages::number_out_of_range(
                        &format!("{:e}", f32::MIN),
                        &format!("{:e}", f32::MAX),
                    ),
                ));
            }
            visitor.visit_f32(value as f32)
        })
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| visitor.visit_f64(de.number()?))
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let text = de.text()?;
            let mut chars = text.chars();
            match (chars.next(), chars.next()) {
                (Some(only), None) => visitor.visit_char(only),
                _ => Err(de.fail(
                    "config.invalid-value",
                    messages::invalid_value("a single character", None),
                )),
            }
        })
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| visitor.visit_str(de.text()?))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        // Absence is the only way to leave an optional member unset. A
        // present null goes to the inner type, which refuses it in its own
        // words (CFG-EMPTY-1), unless it is a `DataLiteral`.
        self.run(false, |de| visitor.visit_some(de.clone()))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            if de.mapping()?.is_empty() {
                visitor.visit_unit()
            } else {
                Err(de.fail(
                    "config.invalid-type",
                    messages::invalid_type("an empty mapping", de.found()),
                ))
            }
        })
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        if let Some(tag) = name.strip_prefix(TAGGED_PREFIX) {
            return self.run(false, |de| {
                de.mapping()?;
                visitor.visit_enum(TaggedAccess {
                    de: de.clone(),
                    tag,
                })
            });
        }
        if let Some(shapes) = name.strip_prefix(SHAPE_PREFIX) {
            return self.run(false, |de| {
                let accepted: Vec<&str> = shapes
                    .split(',')
                    .filter(|shape| !shape.is_empty())
                    .collect();
                let shape = match &de.site.node.value {
                    NodeValue::Null => return Err(de.null_error(false)),
                    NodeValue::Sequence(_) => "list",
                    NodeValue::Mapping(_) => "mapping",
                    _ => "scalar",
                };
                if !accepted.contains(&shape) {
                    return Err(de.fail(
                        "config.invalid-type",
                        messages::wrong_shape(&accepted, de.found()),
                    ));
                }
                visitor.visit_enum(ShapeAccess {
                    de: de.clone(),
                    shape,
                })
            });
        }
        if name == DATA_LITERAL {
            return self.run(false, |de| match &de.site.node.value {
                NodeValue::Sequence(_) | NodeValue::Mapping(_) => Err(de.fail(
                    "config.invalid-type",
                    messages::invalid_type(crate::types::DATA_LITERAL_EXPECTED, de.found()),
                )),
                _ => {
                    let mut literal = de.clone();
                    literal.allow_null = true;
                    visitor.visit_newtype_struct(literal)
                }
            });
        }
        if name == BOUNDED {
            let expecting = Expecting(&visitor).to_string();
            let bounds = parse_bounds(&expecting);
            return self.run(false, |de| {
                let mut bounded = de.clone();
                bounded.bounds = bounds;
                visitor.visit_newtype_struct(bounded)
            });
        }
        self.run(true, |de| visitor.visit_newtype_struct(de.clone()))
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let items = de.sequence()?;
            de.visit_items(items, visitor, None)
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let items = de.sequence()?;
            de.visit_items(items, visitor, Some(len))
        })
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.run(false, |de| {
            let entries = de.mapping()?;
            visitor.visit_map(MapAccess::new(de, entries))
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.run(true, |de| {
            let entries = de.mapping()?;
            let mut access = StructAccess::new(de, entries, fields);
            let result = visitor.visit_map(&mut access);
            access.finish();
            result.map_err(|error| access.place_duplicate(error))
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.run(false, |de| match &de.site.node.value {
            NodeValue::String(text) => visitor.visit_enum(UnitEnum {
                de: de.clone(),
                name: &text.text,
            }),
            NodeValue::Mapping(entries) if entries.len() == 1 => visitor.visit_enum(ExternalEnum {
                de: de.child(&entries[0]),
                entry: &entries[0],
            }),
            NodeValue::Mapping(_) => Err(de.fail(
                "config.invalid-type",
                messages::single_variant_key(variants),
            )),
            NodeValue::Null => Err(de.null_error(false)),
            NodeValue::Sequence(_) => Err(de.fail(
                "config.invalid-type",
                messages::unknown_variant(variants, None),
            )),
            _ => Err(de.fail(
                "config.unknown-variant",
                messages::unknown_variant(variants, None),
            )),
        })
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
}

/// A visitor's `expecting` text, which carries a bounded integer's bounds.
struct Expecting<'v, V>(&'v V);

impl<'de, V: Visitor<'de>> fmt::Display for Expecting<'_, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.expecting(formatter)
    }
}

fn parse_bounds(expecting: &str) -> Option<(i128, i128)> {
    let rest = expecting.strip_prefix(BOUNDED_EXPECTING)?;
    let (minimum, maximum) = rest.split_once(" to ")?;
    Some((minimum.parse().ok()?, maximum.parse().ok()?))
}

// ----- access types -----

struct SeqAccess<'p, 'a> {
    parent: &'p NodeDe<'a>,
    items: &'a [Node],
    index: usize,
}

impl<'de> de::SeqAccess<'de> for SeqAccess<'_, '_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        let Some(item) = self.items.get(self.index) else {
            return Ok(None);
        };
        let de = self.parent.item(self.index, item);
        self.index += 1;
        de.seed(seed).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len() - self.index)
    }
}

/// Every member of a mapping, for maps and self-describing visitors.
struct MapAccess<'p, 'a> {
    parent: &'p NodeDe<'a>,
    entries: &'a [Entry],
    index: usize,
    pending: Option<&'a Entry>,
}

impl<'p, 'a> MapAccess<'p, 'a> {
    fn new(parent: &'p NodeDe<'a>, entries: &'a [Entry]) -> MapAccess<'p, 'a> {
        MapAccess {
            parent,
            entries,
            index: 0,
            pending: None,
        }
    }
}

impl<'de> de::MapAccess<'de> for MapAccess<'_, '_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        while let Some(entry) = self.entries.get(self.index) {
            self.index += 1;
            let path = self.parent.site.child_path(&entry.key);
            if self.parent.is_removed(&path) {
                continue;
            }
            self.pending = Some(entry);
            // A key type that converts after reading the text, such as
            // `LocalId`, fails outside `KeyDe`; its error belongs at the key.
            let key = KeyDe {
                entry,
                path: path.clone(),
            };
            return seed
                .deserialize(key)
                .map(Some)
                .map_err(|error| KeyDe { entry, path }.locate(error));
        }
        Ok(None)
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, Error> {
        let entry = self
            .pending
            .take()
            .expect("serde asks for a value only after its key");
        self.parent.child(entry).seed(seed)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len() - self.index)
    }
}

enum Pending<'a> {
    None,
    Block,
    Entry(&'a Entry),
}

enum Disposition {
    Yield,
    Skip,
    Unknown,
}

/// The members of a struct: known keys go to the visitor, unknown keys to
/// the sink, shared blocks first.
struct StructAccess<'p, 'a> {
    parent: &'p NodeDe<'a>,
    entries: &'a [Entry],
    fields: Vec<&'static str>,
    blocks_fields: Vec<&'static str>,
    blocks: Option<Rc<Blocks>>,
    is_view: bool,
    block_index: usize,
    index: usize,
    pending: Pending<'a>,
    /// The line of the unknown key that listed the accepted keys, so later
    /// unknown keys of this mapping point at it instead of repeating it.
    listed_at: Cell<Option<usize>>,
}

impl<'p, 'a> StructAccess<'p, 'a> {
    fn new(
        parent: &'p NodeDe<'a>,
        entries: &'a [Entry],
        all_fields: &'static [&'static str],
    ) -> StructAccess<'p, 'a> {
        let (blocks_fields, fields): (Vec<&'static str>, Vec<&'static str>) = all_fields
            .iter()
            .copied()
            .partition(|field| field.starts_with(SHARED_BLOCK_PREFIX));
        let is_view = parent.view.is_some();
        let blocks = match &parent.view {
            Some(blocks) => {
                // A shared block takes its own members before the host sees
                // any key.
                let mut claimed = blocks.claimed.borrow_mut();
                for entry in entries {
                    if fields.contains(&entry.key.as_str()) {
                        claimed.insert(entry.key.clone());
                    }
                }
                blocks.fields.borrow_mut().extend(fields.iter().copied());
                Some(Rc::clone(blocks))
            }
            None if !blocks_fields.is_empty() => Some(Rc::new(Blocks::default())),
            None => None,
        };
        StructAccess {
            parent,
            entries,
            fields,
            blocks_fields,
            blocks,
            is_view,
            block_index: 0,
            index: 0,
            pending: Pending::None,
            listed_at: Cell::new(None),
        }
    }

    fn disposition(&self, entry: &Entry, path: &str) -> Disposition {
        let key = entry.key.as_str();
        if self.parent.exclude == Some(key) || self.parent.is_removed(path) {
            return Disposition::Skip;
        }
        let known = self.fields.contains(&key);
        if self.parent.site.place == Place::Root && (key == "apiVersion" || key == "kind") && !known
        {
            // The envelope members were checked before decoding.
            return Disposition::Skip;
        }
        if self.is_view {
            return if known {
                Disposition::Yield
            } else {
                Disposition::Skip
            };
        }
        if let Some(blocks) = &self.blocks {
            if blocks.claimed.borrow().contains(key) {
                return Disposition::Skip;
            }
        }
        if known {
            Disposition::Yield
        } else {
            Disposition::Unknown
        }
    }

    fn report_unknown(&self, entry: &Entry, path: String) {
        // The tag first, since it names the form; then the shared blocks'
        // members, which usually open the mapping; then the host's own.
        let mut accepted: Vec<&str> = self.parent.exclude.into_iter().collect();
        if let Some(blocks) = &self.blocks {
            accepted.extend(blocks.fields.borrow().iter().copied());
        }
        accepted.extend(self.fields.iter().copied());
        let text = if self.parent.site.place == Place::Root && entry.key.starts_with("x-") {
            messages::extension_key(&entry.key)
        } else if messages::names_a_close_key(&entry.key, &accepted) || accepted.is_empty() {
            messages::unknown_key(&entry.key, Some(&accepted))
        } else if let Some(line) = self.listed_at.get() {
            messages::unknown_key_listed_above(&entry.key, line)
        } else {
            self.listed_at.set(Some(entry.key_span.start.line));
            messages::unknown_key(&entry.key, Some(&accepted))
        };
        self.parent.ctx.record(Problem::error(
            "config.unknown-key",
            path,
            Some(entry.key_span.start),
            text,
        ));
    }

    /// Place a member given twice at the key that repeated it. Two keys of
    /// one mapping are never equal (the reader refused that before
    /// decoding), so the repeat is an accepted alternative spelling, and the
    /// visitor refused it as soon as its key was read.
    fn place_duplicate(&self, error: Error) -> Error {
        match (*error.0, &self.pending) {
            (Inner::Located(problem), _) => Error::located(problem),
            (Inner::Unlocated(Kind::DuplicateField(field)), Pending::Entry(entry)) => {
                Error::located(Problem::error(
                    "config.duplicate-key",
                    self.parent.site.child_path(&entry.key),
                    Some(entry.key_span.start),
                    messages::duplicate_member(field),
                ))
            }
            (Inner::Unlocated(kind), _) => Error::unlocated(kind),
        }
    }

    /// Report the unknown keys the visitor did not reach, when it stopped at
    /// an error. Skipped while a shared block is still undecoded, since its
    /// members are not known yet.
    fn finish(&mut self) {
        if self.is_view || self.block_index < self.blocks_fields.len() {
            return;
        }
        while let Some(entry) = self.entries.get(self.index) {
            self.index += 1;
            let path = self.parent.site.child_path(&entry.key);
            if let Disposition::Unknown = self.disposition(entry, &path) {
                self.report_unknown(entry, path);
            }
        }
    }
}

impl<'de> de::MapAccess<'de> for StructAccess<'_, '_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        if let Some(name) = self.blocks_fields.get(self.block_index) {
            self.block_index += 1;
            self.pending = Pending::Block;
            let key: de::value::StrDeserializer<'_, Error> = de::value::StrDeserializer::new(name);
            return seed.deserialize(key).map(Some);
        }
        while let Some(entry) = self.entries.get(self.index) {
            self.index += 1;
            let path = self.parent.site.child_path(&entry.key);
            match self.disposition(entry, &path) {
                Disposition::Yield => {
                    self.pending = Pending::Entry(entry);
                    return seed.deserialize(KeyDe { entry, path }).map(Some);
                }
                Disposition::Skip => {}
                Disposition::Unknown => self.report_unknown(entry, path),
            }
        }
        Ok(None)
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, Error> {
        match std::mem::replace(&mut self.pending, Pending::None) {
            Pending::Entry(entry) => self.parent.child(entry).seed(seed),
            Pending::Block => {
                let mut block = self.parent.clone();
                block.view = self.blocks.clone();
                block.seed(seed)
            }
            Pending::None => panic!("serde asks for a value only after its key"),
        }
    }
}

/// A mapping key, as text.
struct KeyDe<'a> {
    entry: &'a Entry,
    path: String,
}

impl KeyDe<'_> {
    fn locate(&self, error: Error) -> Error {
        match *error.0 {
            Inner::Located(problem) => Error::located(problem),
            Inner::Unlocated(kind) => {
                let at = Some(self.entry.key_span.start);
                let path = self.path.clone();
                let problem = match kind {
                    Kind::UnknownVariant(expected, suggestion) => Problem::error(
                        "config.unknown-variant",
                        path,
                        at,
                        messages::unknown_variant(expected, suggestion),
                    ),
                    Kind::Custom(text) => match parse_protocol(&text) {
                        Some(Protocol::Expected { expected, action }) => Problem::error(
                            "config.invalid-value",
                            path,
                            at,
                            messages::invalid_value(&expected, Some(&action)),
                        ),
                        _ => Problem::error(
                            "config.invalid-value",
                            path,
                            at,
                            messages::invalid_value_generic(),
                        ),
                    },
                    Kind::InvalidType(expected) | Kind::InvalidValue(expected) => {
                        let text = match safe_expected(&expected) {
                            Some(expected) => messages::invalid_value(&expected, None),
                            None => messages::invalid_value_generic(),
                        };
                        Problem::error("config.invalid-value", path, at, text)
                    }
                    _ => Problem::error(
                        "config.invalid-value",
                        path,
                        at,
                        messages::invalid_value_generic(),
                    ),
                };
                Error::located(problem)
            }
        }
    }
}

impl<'de> de::Deserializer<'de> for KeyDe<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let result = visitor.visit_str(&self.entry.key);
        result.map_err(|error| self.locate(error))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let key = KeyDe {
            entry: self.entry,
            path: self.path.clone(),
        };
        let result = visitor.visit_newtype_struct(key);
        result.map_err(|error| self.locate(error))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let key = KeyDe {
            entry: self.entry,
            path: self.path.clone(),
        };
        let result = visitor.visit_some(key);
        result.map_err(|error| self.locate(error))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        let access = KeyEnum {
            name: &self.entry.key,
        };
        let result = visitor.visit_enum(access);
        result.map_err(|error| self.locate(error))
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct
        identifier ignored_any
    }
}

/// An enum named by a mapping key: unit variants only.
struct KeyEnum<'a> {
    name: &'a str,
}

impl<'de, 'a> de::EnumAccess<'de> for KeyEnum<'a> {
    type Error = Error;
    type Variant = UnitOnly;

    fn variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<(S::Value, UnitOnly), Error> {
        let name: de::value::StrDeserializer<'_, Error> =
            de::value::StrDeserializer::new(self.name);
        Ok((seed.deserialize(name)?, UnitOnly))
    }
}

struct UnitOnly;

impl<'de> de::VariantAccess<'de> for UnitOnly {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, _: T) -> Result<T::Value, Error> {
        Err(Error::unlocated(Kind::InvalidType("a key".to_string())))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, _: V) -> Result<V::Value, Error> {
        Err(Error::unlocated(Kind::InvalidType("a key".to_string())))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Error> {
        Err(Error::unlocated(Kind::InvalidType("a key".to_string())))
    }
}

/// An enum written as text: a unit variant.
struct UnitEnum<'a> {
    de: NodeDe<'a>,
    name: &'a str,
}

impl<'de, 'a> de::EnumAccess<'de> for UnitEnum<'a> {
    type Error = Error;
    type Variant = UnitVariant<'a>;

    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, UnitVariant<'a>), Error> {
        let name: de::value::StrDeserializer<'_, Error> =
            de::value::StrDeserializer::new(self.name);
        let value = seed.deserialize(name)?;
        Ok((
            value,
            UnitVariant {
                de: self.de,
                name: self.name,
            },
        ))
    }
}

struct UnitVariant<'a> {
    de: NodeDe<'a>,
    name: &'a str,
}

impl<'de> de::VariantAccess<'de> for UnitVariant<'_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, _: T) -> Result<T::Value, Error> {
        // The name matched a declared variant, so it is an accepted value
        // and may be named.
        Err(self
            .de
            .fail("config.invalid-type", messages::variant_not_unit(self.name)))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, _: V) -> Result<V::Value, Error> {
        Err(self
            .de
            .fail("config.invalid-type", messages::variant_not_unit(self.name)))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Error> {
        Err(self
            .de
            .fail("config.invalid-type", messages::variant_not_unit(self.name)))
    }
}

/// An externally tagged enum: a mapping with one key, the variant's name
/// (CFG-ID-7).
struct ExternalEnum<'a> {
    /// The decoder for the variant's value.
    de: NodeDe<'a>,
    entry: &'a Entry,
}

impl<'de, 'a> de::EnumAccess<'de> for ExternalEnum<'a> {
    type Error = Error;
    type Variant = ExternalVariant<'a>;

    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, ExternalVariant<'a>), Error> {
        let key = KeyDe {
            entry: self.entry,
            path: self.de.site.path.clone(),
        };
        let value = seed.deserialize(key)?;
        Ok((
            value,
            ExternalVariant {
                de: self.de,
                entry: self.entry,
            },
        ))
    }
}

struct ExternalVariant<'a> {
    de: NodeDe<'a>,
    entry: &'a Entry,
}

impl<'de> de::VariantAccess<'de> for ExternalVariant<'_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Err(Error::located(Problem::error(
            "config.invalid-type",
            self.de.site.path.clone(),
            Some(self.entry.key_span.start),
            messages::variant_is_unit(&self.entry.key),
        )))
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        self.de.seed(seed)
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_tuple(self.de, len, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_struct(self.de, "", fields, visitor)
    }
}

/// An internally tagged union: the tag member names the variant, whose
/// members sit beside it (CFG-ID-7).
struct TaggedAccess<'a> {
    de: NodeDe<'a>,
    tag: &'static str,
}

/// The variants an enum's derived identifier accepts, learned by offering a
/// name no enum declares.
fn probe_variants<'de, S: DeserializeSeed<'de>>(seed: S) -> &'static [&'static str] {
    let probe: de::value::StrDeserializer<'_, Error> =
        de::value::StrDeserializer::new(PROBE_VARIANT);
    match seed.deserialize(probe) {
        Err(error) => match *error.0 {
            Inner::Unlocated(Kind::UnknownVariant(variants, _)) => variants,
            _ => &[],
        },
        Ok(_) => &[],
    }
}

impl<'de, 'a> de::EnumAccess<'de> for TaggedAccess<'a> {
    type Error = Error;
    type Variant = TaggedVariant<'a>;

    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, TaggedVariant<'a>), Error> {
        let mut variant = self.de.clone();
        variant.exclude = Some(self.tag);
        let Some(entry) = self.de.site.node.get(self.tag) else {
            let variants = probe_variants(seed);
            return Err(Error::located(Problem::error(
                "config.missing-key",
                self.de.site.path.clone(),
                self.de.site.mapping_at(),
                messages::missing_tag(self.tag, variants),
            )));
        };
        let tag = self.de.child(entry);
        match &entry.value.value {
            // A tag is a name, so a number is not told to become text.
            NodeValue::String(_) if entry.value.unrepresentable().is_none() => {}
            NodeValue::Null => {
                let variants = probe_variants(seed);
                return Err(tag.fail("config.null-value", messages::null_tag(variants)));
            }
            _ => {
                let variants = probe_variants(seed);
                return Err(tag.fail(
                    "config.invalid-type",
                    messages::invalid_type(
                        &format!("one of {}", messages::list(variants)),
                        tag.found(),
                    ),
                ));
            }
        }
        let value = seed.deserialize(tag)?;
        Ok((
            value,
            TaggedVariant {
                de: variant,
                tag: self.tag,
            },
        ))
    }
}

struct TaggedVariant<'a> {
    de: NodeDe<'a>,
    tag: &'static str,
}

impl<'de> de::VariantAccess<'de> for TaggedVariant<'_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        // CFG-SCHEMA-8 asks for `Variant {}`; a unit variant still refuses
        // every member beside the tag.
        let entries = self.de.mapping()?;
        for entry in entries {
            let path = self.de.site.child_path(&entry.key);
            if entry.key == self.tag || self.de.is_removed(&path) {
                continue;
            }
            self.de.ctx.record(Problem::error(
                "config.unknown-key",
                path,
                Some(entry.key_span.start),
                messages::unknown_key(&entry.key, Some(&[self.tag])),
            ));
        }
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        self.de.seed(seed)
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, _: V) -> Result<V::Value, Error> {
        Err(self.de.fail(
            "config.invalid-type",
            messages::developer_misuse("a tagged union variant must be a struct variant"),
        ))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_struct(self.de, "", fields, visitor)
    }
}

/// A node-kind union: the variant is the node's kind.
struct ShapeAccess<'a> {
    de: NodeDe<'a>,
    shape: &'static str,
}

impl<'de, 'a> de::EnumAccess<'de> for ShapeAccess<'a> {
    type Error = Error;
    type Variant = ShapeVariant<'a>;

    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, ShapeVariant<'a>), Error> {
        let shape: de::value::StrDeserializer<'_, Error> =
            de::value::StrDeserializer::new(self.shape);
        let value = seed.deserialize(shape)?;
        Ok((value, ShapeVariant { de: self.de }))
    }
}

struct ShapeVariant<'a> {
    de: NodeDe<'a>,
}

impl<'de> de::VariantAccess<'de> for ShapeVariant<'_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Err(self.de.fail(
            "config.invalid-type",
            messages::developer_misuse("a node-kind union variant must hold one value"),
        ))
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        self.de.seed(seed)
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, _: V) -> Result<V::Value, Error> {
        Err(self.de.fail(
            "config.invalid-type",
            messages::developer_misuse("a node-kind union variant must hold one value"),
        ))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Error> {
        Err(self.de.fail(
            "config.invalid-type",
            messages::developer_misuse("a node-kind union variant must hold one value"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::safe_expected;

    #[test]
    fn cfg_sec_3_expected_text_from_serde_and_the_reader_is_shown() {
        for (expected, shown) in [
            ("a string", "text"),
            ("a sequence", "a list"),
            ("struct Duration", "a mapping"),
            ("a nonzero u32", "a whole number other than 0"),
            ("a key", "a key"),
            (
                "null, a boolean, a number, or text",
                "null, a boolean, a number, or text",
            ),
            ("a whole number from 1 to 10", "a whole number from 1 to 10"),
        ] {
            assert_eq!(
                safe_expected(expected).as_deref(),
                Some(shown),
                "{expected:?}"
            );
        }
    }

    #[test]
    fn cfg_sec_3_text_the_reader_cannot_vouch_for_is_dropped() {
        for expected in [
            "a link whose scheme is not s3cr3t",
            "a JSON object with unique members",
            "a mapping whose `type` member names its form",
            "a whole number from 1 to s3cr3t",
            "",
        ] {
            assert_eq!(safe_expected(expected), None, "{expected:?}");
        }
    }
}
