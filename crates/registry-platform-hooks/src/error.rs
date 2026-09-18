// SPDX-License-Identifier: Apache-2.0

//! The run-time failure taxonomy every product reports for hook failures, so
//! that every product reports the same thing for the same failure, and the
//! bounded rendering every diagnostic in this crate puts untrusted text
//! through.

/// One of the five run-time failure categories.
///
/// The per-kind mapping, fixed by the design note:
///
/// | category | local kinds (`rhai`, `wasm`) | `url` kind |
/// |---|---|---|
/// | [`Deadline`](Self::Deadline) | epoch deadline reached | attempt timeout reached |
/// | [`Resource`](Self::Resource) | fuel, memory, table, input or output ceiling | response body over ceiling |
/// | [`Execution`](Self::Execution) | trap or script error | non-2xx status |
/// | [`Source`](Self::Source) | module or script refused at prepare | malformed response body |
/// | [`Unavailable`](Self::Unavailable) | not applicable | DNS, connect or TLS failure |
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorCategory {
    /// A budget of time ran out: the epoch deadline on a local kind, the
    /// attempt timeout on a `url` kind.
    Deadline,
    /// A budget of space or fuel ran out: fuel, memory, table, input or output
    /// ceiling on a local kind; a response body over the ceiling on a `url`
    /// kind.
    Resource,
    /// The handler ran and failed: a trap or script error on a local kind, a
    /// non-2xx status on a `url` kind.
    Execution,
    /// The handler input was refused before or after the run: module or script
    /// refused at prepare on a local kind, a malformed response body on a
    /// `url` kind.
    Source,
    /// The handler could not be reached. Only the `url` kind reports this:
    /// DNS, connect or TLS failure. Not applicable to local kinds, which have
    /// no transport to fail.
    Unavailable,
}

impl ErrorCategory {
    /// Every category, for exhaustive contract tests.
    pub const ALL: [Self; 5] = [
        Self::Deadline,
        Self::Resource,
        Self::Execution,
        Self::Source,
        Self::Unavailable,
    ];

    /// The category's stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Resource => "resource",
            Self::Execution => "execution",
            Self::Source => "source",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The byte ceiling on any single untrusted token a diagnostic repeats.
pub(crate) const MAX_DISPLAYED_TOKEN_BYTES: usize = 128;

/// The byte ceiling on one whole redacted deserializer message.
pub(crate) const MAX_DISPLAYED_MESSAGE_BYTES: usize = 512;

/// The fixed marker a bounded rendering ends with, so a reader can tell that a
/// value was cut rather than short.
pub(crate) const TRUNCATION_MARKER: &str = "...(truncated)";

/// Render one untrusted token for a diagnostic, bounded to
/// [`MAX_DISPLAYED_TOKEN_BYTES`].
///
/// A handler, a remote destination, or an authored document may put a value of
/// any length where a diagnostic names it: a member name, a variant name, an
/// event id. Every such value passes through here, so every `Display` string
/// the crate produces is host-generated and of bounded length.
pub(crate) fn bounded_token(token: &str) -> String {
    bounded(token, MAX_DISPLAYED_TOKEN_BYTES)
}

/// Render one deserializer message for a diagnostic.
///
/// serde repeats the offending value inside an `invalid type:` or
/// `invalid value:` clause. Only the shape word that opens such a clause
/// survives, so the message still says that a string arrived where a sequence
/// was required without repeating the string. Every remaining delimited run,
/// such as the member name an `unknown field` clause quotes, is bounded to
/// [`MAX_DISPLAYED_TOKEN_BYTES`], and the whole message is bounded to
/// [`MAX_DISPLAYED_MESSAGE_BYTES`].
pub(crate) fn redacted_message(message: &str) -> String {
    let dropped = drop_unexpected_values(message);
    bounded(&bound_delimited_runs(&dropped), MAX_DISPLAYED_MESSAGE_BYTES)
}

/// Truncate `text` to `max` bytes on a character boundary, marking the cut.
fn bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut cut = String::with_capacity(end + TRUNCATION_MARKER.len());
    cut.push_str(&text[..end]);
    cut.push_str(TRUNCATION_MARKER);
    cut
}

/// Keep the parts of a deserializer message a reader needs, the shape word and
/// the closed list of alternatives, while the offending value stays out.
fn drop_unexpected_values(message: &str) -> String {
    const CLAUSES: [&str; 2] = ["invalid type: ", "invalid value: "];
    let mut redacted = String::with_capacity(message.len());
    let mut rest = message;
    loop {
        let Some((start, len)) = CLAUSES
            .iter()
            .filter_map(|clause| rest.find(clause).map(|start| (start, clause.len())))
            .min_by_key(|(start, _)| *start)
        else {
            redacted.push_str(rest);
            return redacted;
        };
        let opened = start + len;
        redacted.push_str(&rest[..opened]);
        let (shape, tail) = split_unexpected_value(&rest[opened..]);
        redacted.push_str(shape);
        rest = tail;
    }
}

/// Split one serde `Unexpected` rendering into its shape word and the text
/// that follows the clause, dropping the quoted or backticked value.
fn split_unexpected_value(clause: &str) -> (&str, &str) {
    let bytes = clause.as_bytes();
    let mut index = 0;
    let mut shape_end = None;
    while index < bytes.len() {
        match bytes[index] {
            delimiter @ (b'"' | b'`') => {
                shape_end.get_or_insert(index);
                index = skip_delimited(bytes, index, delimiter);
            }
            b',' => break,
            _ => index += 1,
        }
    }
    let shape_end = shape_end.unwrap_or(index);
    (clause[..shape_end].trim_end(), &clause[index..])
}

/// Bound every quoted or backticked run in a message, keeping its delimiters.
///
/// The member name in an `unknown field` clause is the attacker's own text and
/// is the one part of such a message that has no length of its own.
fn bound_delimited_runs(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut rendered = String::with_capacity(message.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(open) = bytes[cursor..]
            .iter()
            .position(|byte| matches!(byte, b'"' | b'`'))
            .map(|offset| cursor + offset)
        else {
            rendered.push_str(&message[cursor..]);
            return rendered;
        };
        let delimiter = bytes[open];
        let after = skip_delimited(bytes, open, delimiter);
        let closed = after > open + 1 && bytes[after - 1] == delimiter;
        let content_end = if closed { after - 1 } else { bytes.len() };
        rendered.push_str(&message[cursor..=open]);
        rendered.push_str(&bounded(
            &message[open + 1..content_end],
            MAX_DISPLAYED_TOKEN_BYTES,
        ));
        if closed {
            rendered.push(char::from(delimiter));
        }
        cursor = after.min(bytes.len());
    }
    rendered
}

/// Return the offset just past the delimited run that opens at `open`, or the
/// end of the message when the run never closes.
///
/// serde renders a string value with `Debug`, so a delimiter inside the value
/// arrives escaped and must not end the run.
fn skip_delimited(bytes: &[u8], open: usize, delimiter: u8) -> usize {
    let mut index = open + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == delimiter => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_category_set_is_exactly_five_categories() {
        assert_eq!(
            ErrorCategory::ALL,
            [
                ErrorCategory::Deadline,
                ErrorCategory::Resource,
                ErrorCategory::Execution,
                ErrorCategory::Source,
                ErrorCategory::Unavailable,
            ]
        );
    }

    #[test]
    fn category_spellings_are_pinned() {
        let spellings: Vec<&str> = ErrorCategory::ALL
            .iter()
            .map(|category| category.as_str())
            .collect();
        assert_eq!(
            spellings,
            ["deadline", "resource", "execution", "source", "unavailable"]
        );
    }

    #[test]
    fn a_short_token_is_rendered_whole() {
        assert_eq!(
            bounded_token("eligibility.missing_evidence"),
            "eligibility.missing_evidence"
        );
        let at_bound = "x".repeat(MAX_DISPLAYED_TOKEN_BYTES);
        assert_eq!(bounded_token(&at_bound), at_bound);
    }

    #[test]
    fn a_long_token_is_cut_at_the_ceiling_and_marked() {
        let rendered = bounded_token(&"x".repeat(1024 * 1024));
        assert_eq!(
            rendered,
            format!(
                "{}{TRUNCATION_MARKER}",
                "x".repeat(MAX_DISPLAYED_TOKEN_BYTES)
            )
        );
    }

    #[test]
    fn a_token_is_cut_on_a_character_boundary() {
        // Four-byte characters straddle the ceiling, which is not a multiple
        // of four.
        let rendered = bounded_token(&"\u{1f600}".repeat(1024));
        assert!(rendered.ends_with(TRUNCATION_MARKER), "{rendered}");
        let kept = rendered.len() - TRUNCATION_MARKER.len();
        assert!(kept <= MAX_DISPLAYED_TOKEN_BYTES, "{kept} bytes kept");
        assert_eq!(kept % 4, 0, "the cut landed inside a character");
    }

    #[test]
    fn an_unexpected_value_clause_keeps_its_shape_word_and_drops_the_value() {
        assert_eq!(
            redacted_message(r#"invalid type: string "national id 42", expected u64"#),
            "invalid type: string, expected u64"
        );
        assert_eq!(
            redacted_message("invalid value: integer `-1`, expected a positive revision"),
            "invalid value: integer, expected a positive revision"
        );
    }

    #[test]
    fn an_unknown_member_name_is_bounded_but_still_named() {
        let name = "x".repeat(1024 * 1024);
        let rendered = redacted_message(&format!(
            "unknown field `{name}`, expected one of `id`, `type`, `source`"
        ));
        assert!(rendered.starts_with("unknown field `x"), "{rendered}");
        assert!(
            rendered.ends_with("`, expected one of `id`, `type`, `source`"),
            "the closed list survives: {rendered}"
        );
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "no run of the input longer than the token ceiling survives"
        );
    }

    #[test]
    fn a_whole_message_is_bounded_even_without_a_clause() {
        let rendered = redacted_message(&"no clause here ".repeat(1024));
        assert!(rendered.len() <= MAX_DISPLAYED_MESSAGE_BYTES + TRUNCATION_MARKER.len());
        assert!(rendered.ends_with(TRUNCATION_MARKER), "{rendered}");
    }

    #[test]
    fn an_unclosed_delimited_run_is_bounded_too() {
        let rendered = redacted_message(&format!("unknown field `{}", "x".repeat(1024 * 1024)));
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "an unterminated run is bounded like a closed one"
        );
    }
}
