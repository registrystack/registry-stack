// SPDX-License-Identifier: Apache-2.0
//! Every code the reader reports and every sentence it writes (CFG-DIAG-6).
//!
//! Messages name keys, paths, accepted values, bounds, and the expected
//! envelope. They never repeat a scalar value from the file or the
//! environment (CFG-SEC-3): the builders below take no value text.

use crate::diagnostic::{clean, Diagnostic, Related, Severity, Source};
use crate::node::Position;

/// One reader code and what it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeInfo {
    pub code: &'static str,
    pub meaning: &'static str,
}

/// Every code the reader emits. Product codes have three segments; the
/// reader's have two (`yaml.` for the YAML subset, `config.` for envelope,
/// key, and type problems).
pub const CODES: &[CodeInfo] = &[
    CodeInfo { code: "yaml.too-large", meaning: "the document is larger than 1 MiB" },
    CodeInfo { code: "yaml.not-utf8", meaning: "the document is not UTF-8" },
    CodeInfo { code: "yaml.syntax", meaning: "the YAML is not well formed and no narrower code applies" },
    CodeInfo { code: "yaml.tab-indentation", meaning: "a tab is used for indentation" },
    CodeInfo { code: "yaml.unclosed-quote", meaning: "a quoted value is not closed, or its continuation is not indented" },
    CodeInfo { code: "yaml.invalid-escape", meaning: "a backslash in a double-quoted value starts an escape sequence YAML does not define" },
    CodeInfo { code: "yaml.text-after-quote", meaning: "text follows the closing quote of a quoted value" },
    CodeInfo { code: "yaml.colon-in-plain-value", meaning: "a `: ` inside an unquoted value starts a mapping" },
    CodeInfo { code: "yaml.unexpected-end", meaning: "the document ends inside an unfinished construct" },
    CodeInfo { code: "yaml.duplicate-key", meaning: "a mapping holds the same key twice" },
    CodeInfo { code: "yaml.anchor", meaning: "an anchor (`&name`) is used" },
    CodeInfo { code: "yaml.alias", meaning: "an alias (`*name`) is used" },
    CodeInfo { code: "yaml.merge-key", meaning: "a merge key (`<<`) is used" },
    CodeInfo { code: "yaml.tag", meaning: "an explicit tag (`!!str`, `!custom`) is used" },
    CodeInfo { code: "yaml.non-string-key", meaning: "a mapping key is not a string" },
    CodeInfo { code: "yaml.multiple-documents", meaning: "the file holds more than one document" },
    CodeInfo { code: "yaml.ambiguous-number", meaning: "an unquoted value looks like a number but is not a plain decimal" },
    CodeInfo { code: "yaml.control-character", meaning: "a text value holds a control character other than tab, line feed, or carriage return" },
    CodeInfo { code: "yaml.too-deep", meaning: "the document nests deeper than 128 levels" },
    CodeInfo { code: "config.missing-envelope", meaning: "the document is empty, or its top-level mapping lacks apiVersion or kind" },
    CodeInfo { code: "config.wrong-kind", meaning: "kind is not one the reader accepts" },
    CodeInfo { code: "config.unsupported-api-version", meaning: "apiVersion is not one the reader accepts for this kind" },
    CodeInfo { code: "config.retired-api-version", meaning: "apiVersion is retired" },
    CodeInfo { code: "config.deprecated-api-version", meaning: "apiVersion is deprecated (warning)" },
    CodeInfo { code: "config.removed-key", meaning: "a key was removed or renamed" },
    CodeInfo { code: "config.unknown-key", meaning: "a key is not a member of its mapping" },
    CodeInfo { code: "config.missing-key", meaning: "a required member is absent" },
    CodeInfo { code: "config.unknown-variant", meaning: "a value is not one of the accepted names" },
    CodeInfo { code: "config.invalid-type", meaning: "a value has the wrong shape, or a union holds a form it does not accept" },
    CodeInfo { code: "config.invalid-value", meaning: "a value has the right shape but is not valid" },
    CodeInfo { code: "config.invalid-length", meaning: "a list has the wrong number of items" },
    CodeInfo { code: "config.duplicate-key", meaning: "a member is given twice, under two spellings the type accepts" },
    CodeInfo { code: "config.duplicate-item", meaning: "a list that is a set repeats an item" },
    CodeInfo { code: "config.duplicate-id", meaning: "a list of named items repeats an id" },
    CodeInfo { code: "config.null-value", meaning: "a member is null" },
    CodeInfo { code: "config.expected-string", meaning: "a text member holds something other than text" },
    CodeInfo { code: "config.expected-integer", meaning: "an integer member holds something other than an integer" },
    CodeInfo { code: "config.expected-number", meaning: "a number member holds something other than a number" },
    CodeInfo { code: "config.expected-boolean", meaning: "a boolean member holds something other than true or false" },
    CodeInfo { code: "config.out-of-range", meaning: "a number is outside its bounds" },
    CodeInfo { code: "config.substitution", meaning: "a `${...}` expression cannot be filled: it is not well formed, its variable is unset or empty, `${NAME:?message}` refused, or the value holds a NUL byte (reported by a substitution hook)" },
    CodeInfo { code: "config.substitution-not-allowed", meaning: "a `${...}` expression is written where substitution is not allowed, or an envelope member was substituted" },
    CodeInfo { code: "config.too-many-problems", meaning: "the file has more problems than the reader shows; this last diagnostic counts the rest" },
];

/// A problem found while reading, before the file name and artifact are
/// attached.
#[derive(Clone, Debug)]
pub(crate) struct Problem {
    pub severity: Severity,
    pub code: String,
    pub pointer: String,
    pub position: Option<Position>,
    pub message: String,
    pub action: String,
    pub related: Vec<RelatedProblem>,
}

#[derive(Clone, Debug)]
pub(crate) struct RelatedProblem {
    pub pointer: String,
    pub position: Option<Position>,
    pub message: String,
}

impl Problem {
    pub fn error(
        code: &str,
        pointer: impl Into<String>,
        position: Option<Position>,
        text: Text,
    ) -> Problem {
        Problem {
            severity: Severity::Error,
            code: code.to_string(),
            pointer: pointer.into(),
            position,
            message: text.message,
            action: text.action,
            related: Vec::new(),
        }
    }

    pub fn with_related(
        mut self,
        pointer: impl Into<String>,
        position: Option<Position>,
        message: impl Into<String>,
    ) -> Problem {
        self.related.push(RelatedProblem {
            pointer: pointer.into(),
            position,
            message: message.into(),
        });
        self
    }

    pub fn into_diagnostic(self, file: &str, artifact: Option<&str>) -> Diagnostic {
        Diagnostic {
            severity: self.severity,
            code: self.code,
            artifact: artifact.map(str::to_string),
            path: self.pointer,
            message: self.message,
            suggested_action: self.action,
            source: Some(Source {
                file: file.to_string(),
                line: self.position.map(|position| position.line),
                column: self.position.map(|position| position.column),
            }),
            related: self
                .related
                .into_iter()
                .map(|related| Related {
                    file: file.to_string(),
                    line: related.position.map(|position| position.line),
                    column: related.position.map(|position| position.column),
                    path: related.pointer,
                    message: related.message,
                })
                .collect(),
        }
    }
}

/// A message and the action that fixes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Text {
    pub message: String,
    pub action: String,
}

fn text(message: impl Into<String>, action: impl Into<String>) -> Text {
    Text {
        message: message.into(),
        action: action.into(),
    }
}

/// Keys longer than this are shortened in messages; the path still carries
/// the full key.
const KEY_DISPLAY_CHARS: usize = 64;

/// A key as messages show it: in backticks, control characters escaped.
pub(crate) fn key(name: &str) -> String {
    let shortened: String = name.chars().take(KEY_DISPLAY_CHARS).collect();
    let mut out = String::from("`");
    out.push_str(&clean(&shortened));
    if name.chars().count() > KEY_DISPLAY_CHARS {
        out.push_str("...");
    }
    out.push('`');
    out
}

pub(crate) fn list(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("`{}`", clean(value)))
        .collect::<Vec<_>>()
        .join(", ")
}

// ----- YAML subset -----

pub(crate) fn too_large(bound: usize) -> Text {
    text(
        format!("the document is larger than the {bound}-byte (1 MiB) bound every configuration file shares"),
        "Split the content into smaller files, or move large embedded content into its own file.",
    )
}

pub(crate) fn not_utf8() -> Text {
    text(
        "the document is not valid UTF-8 from this position",
        "Save the file as UTF-8.",
    )
}

pub(crate) fn tab_indentation() -> Text {
    text(
        "a tab is used for indentation here; YAML indents with spaces only",
        "Indent with spaces.",
    )
}

pub(crate) fn unclosed_quote() -> Text {
    text(
        "a quoted value starting here is not closed, or continues onto a line that is not indented",
        "Close the quote.",
    )
}

pub(crate) fn invalid_escape() -> Text {
    text(
        "a backslash in the double-quoted value starting here begins an escape sequence YAML does not define",
        "Use single quotes, or double the backslash.",
    )
}

/// `quote` is the quote that closed the value, when the reader found it.
pub(crate) fn text_after_quote(quote: Option<char>) -> Text {
    let action = match quote {
        Some('\'') => "Put the whole value inside the quotes, and write a quote inside single quotes as two (`''`).",
        Some('"') => "Put the whole value inside the quotes, and write a quote inside double quotes as `\\\"`.",
        _ => "Put the whole value inside the quotes.",
    };
    text("text follows the closing quote of a quoted value", action)
}

pub(crate) fn colon_in_plain_value() -> Text {
    text(
        "a `: ` inside an unquoted value starts a mapping, so this line cannot be read",
        "Quote the value.",
    )
}

pub(crate) fn misplaced_colon() -> Text {
    text(
        "the YAML is not well formed here: a `:` starts a mapping where none can start; the line may be indented more than the keys around it, or continue an unquoted value",
        SYNTAX_ACTION,
    )
}

pub(crate) fn unexpected_end(open: Option<(char, usize)>) -> Text {
    let message = match open {
        Some((bracket, line)) => {
            let close = if bracket == '[' { ']' } else { '}' };
            format!(
                "the document ends inside the list or mapping opened with `{bracket}` on line {line}, which needs a closing `{close}`"
            )
        }
        None => "the document ends inside a list or mapping".to_string(),
    };
    text(message, "Complete or remove the unfinished item.")
}

const SYNTAX_ACTION: &str = "Check the indentation and punctuation at this position.";

/// `open` is the innermost bracket still open where the error is, and the
/// line it was opened on.
pub(crate) fn syntax(parser_note: Option<&str>, open: Option<(char, usize)>) -> Text {
    let mut message = "the YAML is not well formed here".to_string();
    let mut action = SYNTAX_ACTION.to_string();
    if let Some((bracket, line)) = open {
        let (collection, close) = if bracket == '[' {
            ("list", ']')
        } else {
            ("mapping", '}')
        };
        message.push_str(&format!(
            ", inside the {collection} opened with `{bracket}` on line {line}"
        ));
        action = format!(
            "Close the {collection} with `{close}` where it ends, or check the punctuation at this position."
        );
    }
    if let Some(note) = parser_note {
        message.push_str(&format!(" (the parser reports: {note})"));
    }
    text(message, action)
}

pub(crate) fn tab_after_colon() -> Text {
    text(
        "a tab after `:` is not read as the space before an unquoted value",
        "Write a space after `:` in place of the tab.",
    )
}

pub(crate) fn duplicate_key() -> Text {
    text(
        "the key is already defined in this mapping",
        "Keep one definition of the key.",
    )
}

pub(crate) fn duplicate_key_note() -> &'static str {
    "the first definition"
}

pub(crate) fn anchor() -> Text {
    text(
        "an anchor (`&name`) is not supported",
        "Remove the anchor and write the value in full where it is used.",
    )
}

pub(crate) fn alias() -> Text {
    text(
        "an alias (`*name`) is not supported; a lone `*` is not a wildcard",
        "Write the value in full where it is used, or quote it if it is text such as `*`.",
    )
}

pub(crate) fn merge_key() -> Text {
    text(
        "a merge key (`<<`) is not supported",
        "Write the value in full where it is used.",
    )
}

pub(crate) fn tag() -> Text {
    text(
        "an explicit tag (`!!str`, `!name`) is not supported",
        "Remove the tag; quote the value if it is text.",
    )
}

pub(crate) fn non_string_key(kind: &str) -> Text {
    text(
        format!("this mapping key is {kind}; keys are text"),
        "Quote the key to make it text.",
    )
}

pub(crate) fn complex_key() -> Text {
    text(
        "this mapping key is a list or a mapping; keys are text",
        "Use a text key.",
    )
}

pub(crate) fn multiple_documents() -> Text {
    text(
        "a second YAML document starts here; a file holds one document",
        "Remove the `---` line and what follows it, or move the second document to its own file.",
    )
}

pub(crate) fn ambiguous_number() -> Text {
    text(
        "this unquoted value looks like a number but is not a plain decimal, and YAML versions read it differently",
        "Write the number in decimal digits; quote it only where the key takes text.",
    )
}

pub(crate) fn control_character() -> Text {
    text(
        "the text holds a control character other than tab, line feed, or carriage return",
        "Remove the character; in a double-quoted value, look for an escape such as `\\0`, `\\a`, `\\e`, or `\\x01`.",
    )
}

pub(crate) fn too_many_problems(hidden: usize) -> Text {
    let message = if hidden == 1 {
        "1 more problem in this file is not shown".to_string()
    } else {
        format!("{hidden} more problems in this file are not shown")
    };
    text(
        message,
        "Fix the problems shown, then check the file again.",
    )
}

pub(crate) fn too_deep(bound: usize) -> Text {
    text(
        format!("the document nests deeper than {bound} levels"),
        "Flatten the structure.",
    )
}

pub(crate) fn literal_out_of_range(integer: bool) -> Text {
    if integer {
        text(
            format!(
                "this integer is outside the range the reader represents, from {} to {}",
                i64::MIN,
                u64::MAX
            ),
            "Write a smaller integer, or quote it if it is text.",
        )
    } else {
        text(
            format!(
                "this number is outside the range of a binary64 number, from {:e} to {:e}",
                f64::MIN,
                f64::MAX
            ),
            "Write a smaller number, or quote it if it is text.",
        )
    }
}

// ----- envelope -----

pub(crate) fn missing_envelope(start: &str) -> Text {
    text(
        "the document is empty; a configuration file starts with apiVersion and kind",
        format!("Start the file with {start}."),
    )
}

pub(crate) fn empty_exempt_document(kind: &str) -> Text {
    text(
        format!("the document is empty; it must hold a `{kind}` document"),
        "Write the document's content; an empty file is never read as one.",
    )
}

pub(crate) fn root_not_mapping(kind: &str, start: &str) -> Text {
    text(
        format!("the document is {kind}; it must be a mapping that holds apiVersion and kind"),
        format!("Write the document as a mapping that starts with {start}."),
    )
}

pub(crate) fn missing_envelope_members(members: &[&str], start: &str) -> Text {
    text(
        format!("the top-level mapping has no {}", members.join(" or ")),
        format!("Start the file with {start}."),
    )
}

pub(crate) fn envelope_substituted(member: &str) -> Text {
    text(
        format!("{member} is never filled by substitution"),
        format!("Write {member} in the file as plain text."),
    )
}

pub(crate) fn envelope_not_string(member: &str) -> Text {
    text(
        format!("{member} must be text"),
        format!("Write {member} as plain text."),
    )
}

/// The document's own kind is not named: it is a value from the file
/// (CFG-SEC-3).
pub(crate) fn wrong_kind(expected: &[&str]) -> Text {
    let expected_phrase = if expected.len() == 1 {
        list(expected)
    } else {
        format!("one of {}", list(expected))
    };
    text(
        format!("kind is not one this command reads; it reads {expected_phrase}"),
        format!("Give this command a {expected_phrase} file, or correct kind if the file is one."),
    )
}

pub(crate) fn unsupported_api_version(kind: &str, accepted: &[&str]) -> Text {
    text(
        format!(
            "apiVersion is not one this command reads for kind `{}`; it reads {}",
            clean(kind),
            list(accepted)
        ),
        format!(
            "Set apiVersion to {}.",
            accepted
                .first()
                .map(|value| format!("`{}`", clean(value)))
                .unwrap_or_else(|| "a supported version".to_string())
        ),
    )
}

pub(crate) fn retired_api_version(version: &str, current: &[&str], replacement: &str) -> Text {
    let message = if current.is_empty() {
        format!("apiVersion `{}` is retired", clean(version))
    } else {
        format!(
            "apiVersion `{}` is retired; the current apiVersion is {}",
            clean(version),
            list(current)
        )
    };
    text(message, replacement.to_string())
}

pub(crate) fn deprecated_api_version(version: &str, current: &[&str]) -> Text {
    text(
        format!("apiVersion `{}` is deprecated", clean(version)),
        format!("Change apiVersion to {}.", list(current)),
    )
}

// ----- keys -----

pub(crate) fn removed_key(name: &str, replacement: &str) -> Text {
    text(
        format!("{} is no longer accepted", key(name)),
        replacement.to_string(),
    )
}

/// An unknown key in a mapping whose accepted keys an earlier unknown key,
/// on `line`, already listed.
pub(crate) fn unknown_key_listed_above(name: &str, line: usize) -> Text {
    text(
        format!("{} is not a member of this mapping", key(name)),
        format!(
            "Remove {}; the accepted keys are listed at line {line}.",
            key(name)
        ),
    )
}

/// Whether [`unknown_key`] names a likely misspelling instead of listing
/// the accepted keys.
pub(crate) fn names_a_close_key(name: &str, accepted: &[&str]) -> bool {
    closest(name, accepted).is_some()
}

/// `accepted` is `None` when the accepted keys are not known: a struct that
/// still uses serde's `flatten` reports only the first unknown key, without
/// the list.
pub(crate) fn unknown_key(name: &str, accepted: Option<&[&str]>) -> Text {
    let message = format!("{} is not a member of this mapping", key(name));
    let Some(accepted) = accepted else {
        return text(message, format!("Remove {}.", key(name)));
    };
    if let Some(close) = closest(name, accepted) {
        return text(
            message,
            format!("Rename {} to {}, or remove it.", key(name), key(close)),
        );
    }
    if accepted.is_empty() {
        return text(
            message,
            format!("Remove {}; this mapping takes no members.", key(name)),
        );
    }
    text(
        message,
        format!(
            "Remove {}; the accepted keys are {}.",
            key(name),
            list(accepted)
        ),
    )
}

pub(crate) fn extension_key(name: &str) -> Text {
    text(
        format!(
            "{} is not a member of this mapping; extension fields are not supported; use a comment",
            key(name)
        ),
        "Remove the key, and write the note as a comment.",
    )
}

pub(crate) fn missing_key(field: &str) -> Text {
    text(
        format!("the required member {} is missing", key(field)),
        format!("Add {}.", key(field)),
    )
}

pub(crate) fn missing_tag(tag: &str, variants: &[&str]) -> Text {
    let action = if variants.is_empty() {
        format!("Add {}.", key(tag))
    } else {
        format!("Add {} with one of {}.", key(tag), list(variants))
    };
    text(
        format!(
            "the member {} is missing; it names which form this mapping takes",
            key(tag)
        ),
        action,
    )
}

pub(crate) fn duplicate_member(field: &str) -> Text {
    text(
        format!(
            "the member {} is given twice, under its name and under another spelling",
            key(field)
        ),
        "Keep one of the two keys.",
    )
}

// ----- values -----
//
// Value messages do not name the member: the diagnostic's path does. They
// start with what was expected (CFG-DIAG-6).

/// The unit word implied by a member's key (CFG-NAME-4).
pub(crate) fn unit_word(member: Option<&str>) -> Option<&'static str> {
    let member = member?;
    const UNITS: &[(&str, &str)] = &[
        ("WorkingDays", "working days"),
        ("Milliseconds", "milliseconds"),
        ("Seconds", "seconds"),
        ("Minutes", "minutes"),
        ("Hours", "hours"),
        ("Days", "days"),
        ("Bytes", "bytes"),
        ("Degrees", "degrees"),
    ];
    for (suffix, word) in UNITS {
        // `timeoutMilliseconds` ends with the unit; a key that is only the
        // unit is written with a lowercase first letter (`milliseconds`).
        let mut alone = suffix.to_string();
        alone[..1].make_ascii_lowercase();
        if member.ends_with(suffix) || member == alone {
            return Some(word);
        }
    }
    None
}

/// What was found where a typed value was expected, as far as messages may
/// say it. Never the value itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Found {
    Null,
    Boolean,
    Integer,
    Number,
    /// Quoted text that would read as an integer or a number unquoted.
    QuotedNumber,
    /// Quoted text that would read as a boolean unquoted.
    QuotedBoolean,
    /// Any other quoted or block text.
    QuotedText,
    /// Unquoted digits followed by letters (`5s`, `48h`).
    UnitSuffixed,
    /// Other unquoted text that starts with a digit (`1_000`, `1:30`).
    DigitText,
    /// Unquoted `yes`, `no`, `on`, `off`, `y`, or `n` in any case.
    YesNo,
    /// Other unquoted text.
    PlainText,
    /// Text that came from `${...}` substitution.
    Substituted,
    List,
    Mapping,
}

impl Found {
    pub(crate) fn phrase(self) -> &'static str {
        match self {
            Found::Null => "null",
            Found::Boolean => "a boolean",
            Found::Integer => "an integer",
            Found::Number => "a number",
            Found::QuotedNumber | Found::QuotedBoolean | Found::QuotedText => "quoted text",
            Found::UnitSuffixed | Found::DigitText | Found::YesNo | Found::PlainText => {
                "unquoted text"
            }
            Found::Substituted => "substituted text",
            Found::List => "a list",
            Found::Mapping => "a mapping",
        }
    }
}

/// Where a null was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NullPlace {
    /// A member the reader cannot tell is optional: a type with a serde
    /// default is decoded the same way as a required one.
    Member,
    Item,
    /// A position that takes a mapping, such as an optional block.
    Block,
}

const NULL_AFTER_KEY: &str = "null is never a value; an empty value after a key is null too";

pub(crate) fn null_value(place: NullPlace) -> Text {
    match place {
        NullPlace::Item => text(
            "null is never a value; an empty list item is null too",
            "Remove the item, or give a value.",
        ),
        NullPlace::Member => text(
            NULL_AFTER_KEY,
            "Give a value, or remove the key if the member is optional.",
        ),
        NullPlace::Block => text(
            NULL_AFTER_KEY,
            "Give a value (`{}` for a block with no members), or remove the key if the block is optional.",
        ),
    }
}

/// A union's tag given as null: the tag is never optional.
pub(crate) fn null_tag(variants: &[&str]) -> Text {
    let action = if variants.is_empty() {
        "Give a value.".to_string()
    } else {
        format!("Give one of {}.", list(variants))
    };
    text(NULL_AFTER_KEY, action)
}

const SUBSTITUTION_MESSAGE: &str = "substitution fills text values only";
const SUBSTITUTION_ACTION: &str = "Write the value, or template the whole file.";
const QUOTED_ACTION: &str = "Remove the quotes.";

fn substitution() -> Text {
    text(SUBSTITUTION_MESSAGE, SUBSTITUTION_ACTION)
}

const HASH_HINT: &str =
    "A `#` starts a comment only after a space: put a space before the `#` that starts the comment.";

/// The fix for a refused unquoted value holding a `#` with no space before
/// it, which YAML reads as part of the value and not as a comment. The added
/// sentence names no part of the value (CFG-SEC-3).
pub(crate) fn with_hash_hint(text: Text) -> Text {
    Text {
        action: format!("{} {HASH_HINT}", text.action),
        ..text
    }
}

pub(crate) fn expected_string(found: Found) -> Text {
    let action = match found {
        Found::Null | Found::Boolean | Found::Integer | Found::Number => {
            "Quote the value to make it text."
        }
        Found::List | Found::Mapping => "Write a single text value.",
        _ => "Write a text value.",
    };
    text(format!("expected text, not {}", found.phrase()), action)
}

/// The bounds a message states for a whole number: the ones a format
/// declared, or else its type's extremes (CFG-QTY-4), so a message never
/// leaves a bound unsaid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    pub minimum: i128,
    pub maximum: i128,
}

impl Bounds {
    pub(crate) fn new(minimum: i128, maximum: i128) -> Bounds {
        Bounds { minimum, maximum }
    }
}

/// `a whole number of days from 1 to 36500` or `a whole number from 0 to
/// 65535`.
pub(crate) fn whole_number(unit: Option<&str>, bounds: &Bounds) -> String {
    let Bounds { minimum, maximum } = bounds;
    match unit {
        Some(unit) => format!("a whole number of {unit} from {minimum} to {maximum}"),
        None => format!("a whole number from {minimum} to {maximum}"),
    }
}

fn as_digits(unit: Option<&str>) -> String {
    match unit {
        Some(unit) => format!("Write the number of {unit} as digits."),
        None => "Write the number as digits.".to_string(),
    }
}

pub(crate) fn expected_integer(found: Found, unit: Option<&str>, bounds: &Bounds) -> Text {
    let wanted = whole_number(unit, bounds);
    match found {
        Found::QuotedNumber => text(
            format!("expected {wanted}; quoted values are text"),
            QUOTED_ACTION,
        ),
        Found::UnitSuffixed => text(format!("expected {wanted}"), as_digits(unit)),
        Found::DigitText | Found::Number => {
            text(format!("expected {wanted}"), "Write digits only.")
        }
        Found::Substituted => substitution(),
        _ => text(
            format!("expected {wanted}, not {}", found.phrase()),
            format!("Write {wanted}."),
        ),
    }
}

pub(crate) fn expected_number(found: Found, unit: Option<&str>) -> Text {
    match found {
        Found::QuotedNumber => text("expected a number; quoted values are text", QUOTED_ACTION),
        Found::UnitSuffixed => text("expected a number", as_digits(unit)),
        Found::DigitText => text(
            "expected a number",
            "Write digits only, with an optional fraction or exponent.",
        ),
        Found::Substituted => substitution(),
        _ => text(
            format!("expected a number, not {}", found.phrase()),
            "Write a decimal number.",
        ),
    }
}

pub(crate) fn expected_boolean(found: Found) -> Text {
    match found {
        Found::YesNo => text(
            "expected true or false; yes, no, on, and off are text",
            "Write true or false.",
        ),
        Found::QuotedBoolean => text(
            "expected true or false; quoted values are text",
            QUOTED_ACTION,
        ),
        Found::Substituted => substitution(),
        _ => text(
            format!("expected true or false, not {}", found.phrase()),
            "Write true or false.",
        ),
    }
}

pub(crate) fn expected_collection(list_wanted: bool, found: Found) -> Text {
    if found == Found::Substituted {
        return substitution();
    }
    if list_wanted {
        text(
            format!("expected a list, not {}", found.phrase()),
            "Write the items as a list.",
        )
    } else {
        text(
            format!("expected a mapping, not {}", found.phrase()),
            "Write the members as a mapping.",
        )
    }
}

pub(crate) fn integer_out_of_range(unit: Option<&str>, bounds: &Bounds) -> Text {
    let wanted = whole_number(unit, bounds);
    text(
        format!("the value is outside its bounds; expected {wanted}"),
        format!("Write {wanted}."),
    )
}

pub(crate) fn number_out_of_range(min: &str, max: &str) -> Text {
    text(
        format!("the value is outside its bounds; expected a number from {min} to {max}"),
        format!("Write a number from {min} to {max}."),
    )
}

/// The accepted value a refused one most likely meant. It holds only an
/// accepted name, so the refused value is never kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suggestion {
    /// The value differs from this accepted one only in letter case.
    LetterCase(&'static str),
    /// The value is a likely misspelling of this accepted one.
    Close(&'static str),
}

/// The accepted value `written` most likely meant, if any.
pub(crate) fn suggest(written: &str, accepted: &[&'static str]) -> Option<Suggestion> {
    let candidate = closest(written, accepted)?;
    if candidate == written {
        return None;
    }
    if candidate.eq_ignore_ascii_case(written) {
        Some(Suggestion::LetterCase(candidate))
    } else {
        Some(Suggestion::Close(candidate))
    }
}

pub(crate) fn unknown_variant(accepted: &[&str], suggestion: Option<Suggestion>) -> Text {
    if accepted.is_empty() {
        return text(
            "this union accepts no values",
            "Report this to the product maintainers; the format declares a union with no forms.",
        );
    }
    let action = match (suggestion, accepted) {
        (Some(Suggestion::LetterCase(name)), _) => format!("Use `{name}`; letter case matters."),
        (Some(Suggestion::Close(name)), _) => format!("Use `{name}`, the closest accepted value."),
        (None, [only]) => format!("Write {}.", key(only)),
        (None, _) => format!("Use one of {}.", list(accepted)),
    };
    let expected = match accepted {
        [only] => key(only),
        _ => format!("one of {}", list(accepted)),
    };
    text(format!("expected {expected}"), action)
}

pub(crate) fn invalid_type(expected: &str, found: Found) -> Text {
    if found == Found::Substituted {
        return substitution();
    }
    text(
        format!("expected {}, not {}", clean(expected), found.phrase()),
        format!("Write {}.", clean(expected)),
    )
}

pub(crate) fn wrong_shape(accepted: &[&str], found: Found) -> Text {
    if found == Found::Substituted {
        return substitution();
    }
    let shapes: Vec<&str> = accepted
        .iter()
        .map(|shape| match *shape {
            "scalar" => "a single value",
            "list" => "a list",
            "mapping" => "a mapping",
            other => other,
        })
        .collect();
    let joined = match shapes.len() {
        0 => "nothing".to_string(),
        1 => shapes[0].to_string(),
        _ => format!(
            "{} or {}",
            shapes[..shapes.len() - 1].join(", "),
            shapes[shapes.len() - 1]
        ),
    };
    text(
        format!("expected {joined}, not {}", found.phrase()),
        format!("Write {joined}."),
    )
}

pub(crate) fn single_variant_key(variants: &[&str]) -> Text {
    text(
        format!(
            "expected a mapping with exactly one key, naming one of {}",
            list(variants)
        ),
        format!("Write one key from {} with its value.", list(variants)),
    )
}

pub(crate) fn variant_not_unit(variant: &str) -> Text {
    text(
        format!("the form {} takes members", key(variant)),
        format!(
            "Write {} as a key, with its members in a mapping below it.",
            key(variant)
        ),
    )
}

pub(crate) fn variant_is_unit(variant: &str) -> Text {
    text(
        format!("the form {} takes no members", key(variant)),
        format!("Write {} as a single value.", key(variant)),
    )
}

/// `action` is the sentence a type gave through [`crate::Invalid`]; without
/// one, the shared types' rule or a sentence built from `expected` is used.
pub(crate) fn invalid_value(expected: &str, action: Option<&str>) -> Text {
    let message = format!("expected {}", clean(expected));
    if let Some(action) = action.filter(|action| !action.is_empty()) {
        return text(message, clean(action));
    }
    match TYPE_RULES.iter().find(|rule| rule.expected == expected) {
        Some(rule) => text(message, rule.action),
        None => text(message, format!("Write {}.", clean(expected))),
    }
}

pub(crate) fn invalid_value_generic() -> Text {
    text(
        "the value is not valid here",
        "Check the value against the format's reference for this member.",
    )
}

pub(crate) fn invalid_length(expected: &str) -> Text {
    text(
        format!(
            "the list has the wrong number of items; expected {}",
            clean(expected)
        ),
        format!("Give {}.", clean(expected)),
    )
}

pub(crate) fn approximate(expected: Option<&str>) -> Text {
    let message = match expected {
        Some(expected) => format!(
            "a value inside this member must be {}; the format reads this member as a whole, so the reader cannot point to the value",
            clean(expected)
        ),
        None => "a value inside this member is not valid; the format reads this member as a whole, so the reader cannot point to the value".to_string(),
    };
    text(
        message,
        "Check the values inside this member against the format's reference.",
    )
}

pub(crate) fn duplicate_item(first: usize) -> Text {
    text(
        format!("this item repeats the item at index {first}; the list is a set"),
        "Remove the repeated item.",
    )
}

pub(crate) fn duplicate_item_note() -> &'static str {
    "the first occurrence"
}

pub(crate) fn duplicate_id(id_key: &str, first: usize) -> Text {
    text(
        format!(
            "this {} repeats the {} of the item at index {first}; it is unique in this list",
            key(id_key),
            key(id_key)
        ),
        format!("Give each item its own {}.", key(id_key)),
    )
}

pub(crate) fn duplicate_id_note() -> &'static str {
    "the first item with this id"
}

pub(crate) fn developer_misuse(what: &str) -> Text {
    text(
        format!("the reader cannot decode this member: {what}"),
        "Report this to the product maintainers; the format's type is declared in a way the reader does not support.",
    )
}

/// Bound-checked values whose grammar the shared types declare. The
/// `expected` text is what the type reports through `invalid_value`.
pub(crate) struct TypeRule {
    pub expected: &'static str,
    pub action: &'static str,
}

pub(crate) const EXPECT_LOCAL_ID: &str = "a local identifier matching `^[a-z][a-z0-9_-]{0,63}$`";
pub(crate) const EXPECT_EXTERNAL_ID: &str =
    "a non-empty identifier of at most 512 characters without control characters";
pub(crate) const EXPECT_DIGEST: &str =
    "a digest written `sha256:` followed by 64 lowercase hex digits";
pub(crate) const EXPECT_URL: &str =
    "an absolute http or https URL with a host, no user information, and at most 2048 characters";
pub(crate) const EXPECT_DATA_LITERAL: &str = "null, a boolean, a number, or text";

pub(crate) const TYPE_RULES: &[TypeRule] = &[
    TypeRule {
        expected: EXPECT_LOCAL_ID,
        action: "Use lowercase letters, digits, `_`, and `-`, starting with a letter, at most 64 characters.",
    },
    TypeRule {
        expected: EXPECT_EXTERNAL_ID,
        action: "Write the identifier exactly as its issuer gives it, without control characters.",
    },
    TypeRule {
        expected: EXPECT_DIGEST,
        action: "Write the digest as `sha256:` followed by 64 lowercase hex digits.",
    },
    TypeRule {
        expected: EXPECT_URL,
        action: "Write an absolute URL starting with `https://` or `http://`, without user information.",
    },
    TypeRule {
        expected: EXPECT_DATA_LITERAL,
        action: "Write null, true, false, a number, or text.",
    },
];

/// The closest accepted name, when one is a likely misspelling.
fn closest<'a>(name: &str, accepted: &[&'a str]) -> Option<&'a str> {
    let lower = name.to_ascii_lowercase();
    let mut best: Option<(usize, &str)> = None;
    for candidate in accepted {
        if candidate.to_ascii_lowercase() == lower {
            return Some(candidate);
        }
        let distance = edit_distance(name, candidate);
        let limit = if candidate.chars().count() <= 4 { 1 } else { 2 };
        if distance <= limit && best.is_none_or(|(current, _)| distance < current) {
            best = Some((distance, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// Edits between two keys, counting a swap of two neighbouring characters
/// as one edit, since that is the most common misspelling of a key.
fn edit_distance(left: &str, right: &str) -> usize {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    if left.len().abs_diff(right.len()) > 2 {
        return usize::MAX;
    }
    let width = right.len() + 1;
    let mut table = vec![0usize; (left.len() + 1) * width];
    for (i, row) in table.chunks_mut(width).enumerate() {
        row[0] = i;
    }
    for (j, cell) in table[..width].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=left.len() {
        for j in 1..=right.len() {
            let cost = usize::from(left[i - 1] != right[j - 1]);
            let mut best = (table[(i - 1) * width + j] + 1)
                .min(table[i * width + j - 1] + 1)
                .min(table[(i - 1) * width + j - 1] + cost);
            if i > 1 && j > 1 && left[i - 1] == right[j - 2] && left[i - 2] == right[j - 1] {
                best = best.min(table[(i - 2) * width + j - 2] + 1);
            }
            table[i * width + j] = best;
        }
    }
    table[left.len() * width + right.len()]
}
