// SPDX-License-Identifier: Apache-2.0
//! Canonicalization of target-relative request paths.
//!
//! This is a security boundary. A script supplies a path string; before it is
//! ever joined to a base URL it must be proven to be a *single, absolute,
//! target-relative* path with no traversal, no encoding tricks, no query, and
//! no fragment. [`canonicalize_target_relative_path`] is the gate.
//!
//! The strategy is: **percent-decode exactly once, then validate the decoded
//! form**. Decoding first means an attacker cannot smuggle a `.`/`/`/`\` past
//! the segment checks by encoding it (`%2e`, `%2f`, `%5c`). Double-encoding
//! (`%252e`) is rejected because the *first* decode yields a literal `%`
//! followed by hex, which we treat as an invalid leftover escape unless it
//! decodes to an allowed character — and even when it decodes, the resulting
//! `%2e` text is then re-examined and rejected as a dot segment is rebuilt.
//! To keep this airtight we reject any `%` that survives the single decode.
//!
//! Joining to a base URL and matching against an allow-list are deliberately
//! *out of scope* here — they belong to the embedder. This function only
//! decides whether a raw path is structurally safe to consider at all.
//!
//! # No Unicode normalization
//!
//! This module performs **no** Unicode or NFKC normalization, and callers must
//! not normalize the returned path either. Normalization is a traversal vector:
//! NFKC folds characters such as the fullwidth full stop `．` (U+FF0E) onto the
//! ASCII `.`, which would let `／．．／` become `/../` *after* these checks have
//! run. The segment checks here compare against the literal ASCII `.`/`..`
//! only; a future change that adds normalization upstream or downstream would
//! silently re-open the traversal hole, so it is forbidden by contract.

use std::fmt;

/// Why a raw path was rejected. Low-cardinality, non-sensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The raw input was empty.
    Empty,
    /// The path did not begin with exactly one `/`.
    MissingLeadingSlash,
    /// The path began with `//` (multiple leading slashes / protocol-relative).
    MultipleLeadingSlashes,
    /// The path contained a query component (`?`).
    ContainsQuery,
    /// The path contained a fragment component (`#`).
    ContainsFragment,
    /// The path contained a `.` or `..` segment (after decoding).
    TraversalSegment,
    /// The path contained an empty segment (e.g. `//` in the middle).
    EmptySegment,
    /// The path contained an invalid or disallowed percent-encoding.
    InvalidPercentEncoding,
    /// The raw path contained an encoded path separator (`%2f`/`%2F`). An
    /// encoded slash is rejected outright rather than decoded, because turning
    /// `foo%2fbar` into the different resource `foo/bar` is never intended.
    EncodedSeparator,
    /// The decoded path contained a control or otherwise disallowed character.
    DisallowedCharacter,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PathError::Empty => "empty path",
            PathError::MissingLeadingSlash => "path must begin with `/`",
            PathError::MultipleLeadingSlashes => "path must not begin with `//`",
            PathError::ContainsQuery => "path must not contain a query (`?`)",
            PathError::ContainsFragment => "path must not contain a fragment (`#`)",
            PathError::TraversalSegment => "path must not contain `.` or `..` segments",
            PathError::EmptySegment => "path must not contain empty segments",
            PathError::InvalidPercentEncoding => "path contains invalid percent-encoding",
            PathError::EncodedSeparator => "path must not contain an encoded separator (`%2f`)",
            PathError::DisallowedCharacter => "path contains a disallowed character",
        };
        f.write_str(s)
    }
}

impl std::error::Error for PathError {}

/// Percent-decode a single pass over `raw`.
///
/// Returns an error if any `%` is not followed by two hex digits. Crucially we
/// do *not* allow the decoded output to itself contain a `%` that came from an
/// escape (`%25`), because that is the signature of double-encoding; such input
/// is rejected by the caller's "no surviving percent" rule.
fn percent_decode_once(raw: &str) -> Result<String, PathError> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(PathError::InvalidPercentEncoding);
                }
                let hi = hex_val(bytes[i + 1]).ok_or(PathError::InvalidPercentEncoding)?;
                let lo = hex_val(bytes[i + 2]).ok_or(PathError::InvalidPercentEncoding)?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // The decoded bytes must be valid UTF-8 to be a sane path.
    String::from_utf8(out).map_err(|_| PathError::InvalidPercentEncoding)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Detect an encoded forward slash (`%2f`/`%2F`, any hex case) in the raw input.
/// Note this only matches a *single-encoded* slash; a double-encoded one
/// (`%252f`) survives as a literal `%` after one decode and is rejected by the
/// "no surviving percent" rule instead.
fn contains_encoded_slash(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes
        .windows(3)
        .any(|w| w[0] == b'%' && w[1] == b'2' && (w[2] == b'f' || w[2] == b'F'))
}

/// Canonicalize a raw, script-supplied, target-relative path.
///
/// On success returns the (decoded) canonical path, which:
/// * begins with exactly one `/`,
/// * has no `.`/`..`/empty segments,
/// * has no query or fragment,
/// * contains no control characters, backslashes, or surviving `%` escapes.
///
/// This does **not** join a base URL or consult an allow-list.
pub fn canonicalize_target_relative_path(raw: &str) -> Result<String, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }

    // Reject query / fragment on the RAW input first: a `?`/`#` (encoded or
    // not) must never appear. We check the encoded forms here and again after
    // decode so neither `?`/`#` nor `%3f`/`%23` can slip through.
    if raw.contains('?') {
        return Err(PathError::ContainsQuery);
    }
    if raw.contains('#') {
        return Err(PathError::ContainsFragment);
    }

    // Reject an encoded forward slash on the RAW input, before decoding. An
    // encoded separator (`%2f`/`%2F`) is never legitimate here: decoding it
    // would silently turn `foo%2fbar` into the different resource `foo/bar`.
    // This mirrors how the decoded backslash is rejected below.
    if contains_encoded_slash(raw) {
        return Err(PathError::EncodedSeparator);
    }

    // Decode exactly once.
    let decoded = percent_decode_once(raw)?;

    // After a single decode, no `%` may remain. A surviving `%` means the input
    // was double-encoded (`%252e` -> `%2e`) or contained a stray `%`; either
    // way it is rejected.
    if decoded.contains('%') {
        return Err(PathError::InvalidPercentEncoding);
    }

    // Re-check query / fragment on the decoded form (catches `%3f` / `%23`).
    if decoded.contains('?') {
        return Err(PathError::ContainsQuery);
    }
    if decoded.contains('#') {
        return Err(PathError::ContainsFragment);
    }

    // Reject backslashes outright (catches `%5c` after decode); they are a
    // common traversal/normalization vector and never valid in our paths.
    if decoded.contains('\\') {
        return Err(PathError::DisallowedCharacter);
    }

    // Reject control characters (incl. NUL, newline) and DEL.
    if decoded.chars().any(|c| c.is_control()) {
        return Err(PathError::DisallowedCharacter);
    }

    // Must begin with exactly one leading slash.
    if !decoded.starts_with('/') {
        return Err(PathError::MissingLeadingSlash);
    }
    if decoded.starts_with("//") {
        // Covers protocol-relative `//host` and multiple leading slashes.
        return Err(PathError::MultipleLeadingSlashes);
    }

    // Walk the segments after the single leading slash. Reject empty segments
    // (which also catches an interior `//`), and `.`/`..` traversal.
    let body = &decoded[1..];
    // A bare "/" is acceptable: body is empty, zero segments.
    if !body.is_empty() {
        for segment in body.split('/') {
            if segment.is_empty() {
                return Err(PathError::EmptySegment);
            }
            if segment == "." || segment == ".." {
                return Err(PathError::TraversalSegment);
            }
        }
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &str) -> String {
        canonicalize_target_relative_path(raw)
            .unwrap_or_else(|e| panic!("expected accept for {raw:?}, got {e:?}"))
    }
    fn err(raw: &str) -> PathError {
        canonicalize_target_relative_path(raw).expect_err(&format!("expected reject for {raw:?}"))
    }

    #[test]
    fn accepts_normal_absolute_paths() {
        assert_eq!(ok("/trackedEntityInstances"), "/trackedEntityInstances");
        assert_eq!(ok("/api/33/metadata"), "/api/33/metadata");
        assert_eq!(ok("/a/b/c"), "/a/b/c");
        assert_eq!(ok("/"), "/");
        // Hyphens, underscores, digits, dots inside a segment are fine.
        assert_eq!(ok("/v1.2/foo_bar-baz"), "/v1.2/foo_bar-baz");
        // A dot that is not a whole segment is allowed (e.g. file extension).
        assert_eq!(ok("/data.json"), "/data.json");
    }

    #[test]
    fn accepts_safe_percent_encoding_of_normal_chars() {
        // %20 -> space inside a segment is allowed (not a traversal/structural char).
        assert_eq!(ok("/a%20b"), "/a b");
        // Encoded letter decodes and is accepted.
        assert_eq!(ok("/%61bc"), "/abc");
    }

    #[test]
    fn rejects_empty_and_relative() {
        assert_eq!(err(""), PathError::Empty);
        assert_eq!(
            err("trackedEntityInstances"),
            PathError::MissingLeadingSlash
        );
        assert_eq!(err("a/b"), PathError::MissingLeadingSlash);
    }

    #[test]
    fn rejects_multiple_leading_and_protocol_relative() {
        assert_eq!(err("//evil.com/x"), PathError::MultipleLeadingSlashes);
        assert_eq!(err("//"), PathError::MultipleLeadingSlashes);
        assert_eq!(err("///a"), PathError::MultipleLeadingSlashes);
    }

    #[test]
    fn rejects_dot_and_dotdot_segments() {
        assert_eq!(err("/."), PathError::TraversalSegment);
        assert_eq!(err("/.."), PathError::TraversalSegment);
        assert_eq!(err("/a/../b"), PathError::TraversalSegment);
        assert_eq!(err("/a/./b"), PathError::TraversalSegment);
        assert_eq!(err("/../etc/passwd"), PathError::TraversalSegment);
        assert_eq!(err("/a/.."), PathError::TraversalSegment);
    }

    #[test]
    fn rejects_empty_interior_segments() {
        assert_eq!(err("/a//b"), PathError::EmptySegment);
        assert_eq!(err("/a/"), PathError::EmptySegment);
        assert_eq!(err("/a/b//"), PathError::EmptySegment);
    }

    #[test]
    fn rejects_encoded_dot_segments() {
        // %2e -> "." ; %2e%2e -> ".."
        assert_eq!(err("/%2e"), PathError::TraversalSegment);
        assert_eq!(err("/%2e%2e"), PathError::TraversalSegment);
        assert_eq!(err("/a/%2e%2e/b"), PathError::TraversalSegment);
        // Mixed case hex.
        assert_eq!(err("/%2E"), PathError::TraversalSegment);
        assert_eq!(err("/%2E%2e/x"), PathError::TraversalSegment);
    }

    #[test]
    fn rejects_encoded_slash_and_backslash() {
        // An encoded forward slash (`%2f`/`%2F`) is rejected outright on the raw
        // input, BEFORE decoding, so it can never silently become a real `/`
        // and split into a different resource. Any hex case is caught.
        assert_eq!(err("/a%2fb"), PathError::EncodedSeparator);
        assert_eq!(err("/a%2Fb"), PathError::EncodedSeparator);
        // Even when the encoded slashes would otherwise build a traversal or a
        // trailing empty segment, the encoded-separator rejection fires first.
        assert_eq!(err("/a%2f..%2fb"), PathError::EncodedSeparator);
        assert_eq!(err("/a%2f"), PathError::EncodedSeparator);
        // %5c -> "\" backslash is rejected outright (after decode).
        assert_eq!(err("/a%5cb"), PathError::DisallowedCharacter);
        assert_eq!(err("/%5c"), PathError::DisallowedCharacter);
    }

    #[test]
    fn rejects_double_encoding() {
        // %252e -> "%2e" after one decode; the surviving "%" is rejected.
        assert_eq!(err("/%252e"), PathError::InvalidPercentEncoding);
        assert_eq!(err("/%252e%252e/x"), PathError::InvalidPercentEncoding);
        // %252f -> "%2f": the raw encoded-slash check only matches a SINGLE
        // encoding (`%2f`), so this falls through to the surviving-`%` rule.
        assert_eq!(err("/a%252fb"), PathError::InvalidPercentEncoding);
    }

    #[test]
    fn rejects_encoded_forward_slash_outright() {
        // An encoded `/` is rejected on the raw input, before decode, in any hex
        // case — never silently turned into a real separator.
        assert_eq!(err("/a%2fb"), PathError::EncodedSeparator);
        assert_eq!(err("/a%2Fb"), PathError::EncodedSeparator);
        assert_eq!(err("/%2f"), PathError::EncodedSeparator);
        // The encoded-separator check precedes the traversal / empty-segment
        // checks, so these classify as EncodedSeparator (not Traversal/Empty).
        assert_eq!(err("/a%2f..%2fb"), PathError::EncodedSeparator);
        assert_eq!(err("/a%2f"), PathError::EncodedSeparator);
    }

    #[test]
    fn rejects_invalid_percent_encoding() {
        assert_eq!(err("/%"), PathError::InvalidPercentEncoding);
        assert_eq!(err("/%2"), PathError::InvalidPercentEncoding);
        assert_eq!(err("/%zz"), PathError::InvalidPercentEncoding);
        assert_eq!(err("/a%g0b"), PathError::InvalidPercentEncoding);
        // Trailing partial escape.
        assert_eq!(err("/abc%2"), PathError::InvalidPercentEncoding);
    }

    #[test]
    fn rejects_query_and_fragment() {
        assert_eq!(err("/a?b=1"), PathError::ContainsQuery);
        assert_eq!(err("/a#frag"), PathError::ContainsFragment);
        // Encoded `?` (%3f) and `#` (%23) must also be rejected after decode.
        assert_eq!(err("/a%3fb"), PathError::ContainsQuery);
        assert_eq!(err("/a%23b"), PathError::ContainsFragment);
        assert_eq!(err("/a%3Fb"), PathError::ContainsQuery);
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(err("/a%00b"), PathError::DisallowedCharacter); // NUL
        assert_eq!(err("/a%0ab"), PathError::DisallowedCharacter); // newline
        assert_eq!(err("/a%09b"), PathError::DisallowedCharacter); // tab
        assert_eq!(err("/a%7fb"), PathError::DisallowedCharacter); // DEL
    }

    #[test]
    fn rejects_invalid_utf8_after_decode() {
        // 0xFF is not valid UTF-8 on its own.
        assert_eq!(err("/%ff"), PathError::InvalidPercentEncoding);
    }
}
